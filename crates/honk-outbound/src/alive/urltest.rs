use super::collection::DialerCollection;
use super::{
    AliveDialerSet, DEFAULT_GROUP_IDLE_TIMEOUT, IpVersion, ProbeDomain, RECOVERY_SUCCESSES_NEEDED,
    UrlMemberResolver, UrlProbeMember, UrlProbeState, alive_index, probe_backoff,
    probe_failure_threshold,
};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use uuid::Uuid;

const MAX_ACTIVITY_REFRESH_QUANTUM_NS: u64 = 1_000_000_000;
const COARSE_CLOCK_MIN_TIMEOUT: Duration = Duration::from_secs(1);

#[cfg(target_os = "linux")]
#[inline]
pub(super) fn monotonic_coarse_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `CLOCK_MONOTONIC_COARSE` is supported on Linux and writes into
    // the stack-allocated `timespec`.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_COARSE, &mut ts) };
    if rc != 0 || ts.tv_sec < 0 || ts.tv_nsec < 0 {
        return 0;
    }
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

#[inline]
fn use_coarse_clock_for(timeout: Duration) -> bool {
    cfg!(target_os = "linux") && timeout >= COARSE_CLOCK_MIN_TIMEOUT
}

/// How a group participates in idle probe suspension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleGroupKind {
    /// Automatic policy: wakes its direct members on selection and pauses them
    /// again after `idle_timeout` without traffic.
    Automatic,
    /// Selector policy: always counts as idle so unselected direct members stay
    /// suspended; only explicitly chosen members stay probed via `selected_nodes`.
    Selector,
}

/// Group entry for [`AliveDialerSet::sync_idle_groups`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdleGroupRegistration {
    pub name: String,
    pub members: Vec<Uuid>,
    pub idle_timeout: Option<Duration>,
    pub kind: IdleGroupKind,
    /// Non-builtin reachable proxy leaves that keep TCP datapath open for an
    /// automatic group (including reachable subgroups and non-builtin finals).
    pub tcp_recovery_members: Vec<Uuid>,
    /// Subset of `tcp_recovery_members` capable of carrying UDP.
    pub udp_recovery_members: Vec<Uuid>,
}

/// Cache-line-aligned per-group activity state shared between [`AliveDialerSet`]
/// and callers caching a direct handle for lock-free steady-state refreshes.
#[repr(align(64))]
pub struct IdleActivitySlot {
    generation: u64,
    kind: IdleGroupKind,
    use_coarse_clock: bool,
    timeout_ns: u64,
    refresh_quantum_ns: u64,
    /// Monotonic nanoseconds since the slot's clock origin + 1 (`0` = never active).
    pub(super) last_active_ns: AtomicU64,
}

impl IdleActivitySlot {
    fn new(generation: u64, kind: IdleGroupKind, timeout: Duration, last_active_ns: u64) -> Self {
        let timeout_ns = duration_to_ns(timeout);
        let refresh_quantum_ns = if timeout_ns == 0 {
            0
        } else {
            (timeout_ns / 4).clamp(1, MAX_ACTIVITY_REFRESH_QUANTUM_NS)
        };
        Self {
            generation,
            kind,
            use_coarse_clock: use_coarse_clock_for(timeout),
            timeout_ns,
            refresh_quantum_ns,
            last_active_ns: AtomicU64::new(last_active_ns),
        }
    }

    #[inline]
    pub(super) fn is_idle(&self, now_ns: u64) -> bool {
        if self.kind == IdleGroupKind::Selector || self.timeout_ns == 0 {
            return true;
        }
        let last = self.last_active_ns.load(Ordering::Acquire);
        last == 0 || now_ns.saturating_sub(last) >= self.timeout_ns
    }
}

pub(super) struct IdleGroupEntry {
    pub(super) members: Vec<Uuid>,
    pub(super) tcp_recovery_members: Vec<Uuid>,
    pub(super) udp_recovery_members: Vec<Uuid>,
    pub(super) activity: Arc<IdleActivitySlot>,
}

#[derive(Default)]
pub(super) struct IdleGroups {
    pub(super) groups: HashMap<String, IdleGroupEntry>,
    pub(super) node_groups: HashMap<Uuid, Vec<String>>,
}

impl IdleGroups {
    pub(super) fn remove_node(&mut self, node_id: Uuid) {
        if let Some(groups) = self.node_groups.remove(&node_id) {
            for group in groups {
                if let Some(entry) = self.groups.get_mut(&group) {
                    entry.members.retain(|&id| id != node_id);
                }
            }
        }
        for entry in self.groups.values_mut() {
            entry.tcp_recovery_members.retain(|&id| id != node_id);
            entry.udp_recovery_members.retain(|&id| id != node_id);
        }
    }
}

fn dedup_non_builtin(ids: &[Uuid]) -> Vec<Uuid> {
    let mut out = Vec::with_capacity(ids.len());
    for &id in ids {
        if id != honk_config::config::DIRECT_NODE_ID
            && id != honk_config::config::BLOCK_NODE_ID
            && !out.contains(&id)
        {
            out.push(id);
        }
    }
    out
}

fn duration_to_ns(duration: Duration) -> u64 {
    duration.as_nanos().min(u64::MAX as u128) as u64
}

impl AliveDialerSet {
    #[inline]
    pub(super) fn now_ns(&self) -> u64 {
        (self
            .started_at
            .elapsed()
            .as_nanos()
            .min(u64::MAX as u128 - 1) as u64)
            + 1
    }

    #[cfg(target_os = "linux")]
    #[inline]
    pub(super) fn coarse_now_ns(&self) -> u64 {
        monotonic_coarse_ns()
            .saturating_sub(self.started_at_coarse_ns)
            .min(u64::MAX - 1)
            + 1
    }

    #[inline]
    pub(super) fn activity_now_ns(&self, use_coarse_clock: bool) -> u64 {
        #[cfg(target_os = "linux")]
        if use_coarse_clock {
            return self.coarse_now_ns();
        }
        #[cfg(not(target_os = "linux"))]
        let _ = use_coarse_clock;
        self.now_ns()
    }

    #[inline]
    fn is_entry_idle(&self, entry: &IdleGroupEntry) -> bool {
        entry
            .activity
            .is_idle(self.activity_now_ns(entry.activity.use_coarse_clock))
    }

    fn preserve_last_active_ns(
        &self,
        old: Option<&IdleGroupEntry>,
        new_kind: IdleGroupKind,
        new_timeout: Duration,
    ) -> u64 {
        if new_kind == IdleGroupKind::Selector || new_timeout.is_zero() {
            return 0;
        }
        let Some(old) = old else {
            return 0;
        };
        if old.activity.kind != IdleGroupKind::Automatic || old.activity.timeout_ns == 0 {
            return 0;
        }
        let old_last = old.activity.last_active_ns.load(Ordering::Acquire);
        if old_last == 0 {
            return 0;
        }
        let old_now = self.activity_now_ns(old.activity.use_coarse_clock);
        let elapsed = old_now.saturating_sub(old_last);
        if elapsed >= old.activity.timeout_ns || elapsed >= duration_to_ns(new_timeout) {
            return 0;
        }
        let new_use_coarse = use_coarse_clock_for(new_timeout);
        if old.activity.use_coarse_clock == new_use_coarse {
            return old_last;
        }
        self.activity_now_ns(new_use_coarse)
            .saturating_sub(elapsed)
            .max(1)
    }

    /// Replace the whole custom check-URL table (config reload), same
    /// shape as [`AliveDialerSet::sync_idle_groups`]: `groups` is
    /// `(group name, check_url)` for every group that has a custom
    /// `check_url`. Entries for groups absent from `groups` are dropped;
    /// per-(tag, url) probe state and latency data survive as long as the
    /// URL itself is still in use by some group.
    pub fn sync_group_check_urls(&self, groups: &[(String, String)]) {
        {
            let mut map = self.group_check_urls.write();
            map.clear();
            for (group, url) in groups {
                map.insert(group.clone(), url.clone());
            }
            self.reset_group_health_observations();
        }
        let (active_groups, active_urls): (HashSet<String>, HashSet<String>) = {
            let map = self.group_check_urls.read();
            (
                map.keys().cloned().collect(),
                map.values().cloned().collect(),
            )
        };
        self.pending_url_group_wakes
            .lock()
            .retain(|group| active_groups.contains(group));
        self.url_check_ips
            .write()
            .retain(|url, _| active_urls.contains(url));
        self.url_states
            .write()
            .retain(|(_, url), _| active_urls.contains(url));
        self.url_collections
            .write()
            .retain(|(_, url), _| active_urls.contains(url));
    }

    /// Groups with a custom check URL: `(group name, url)`.
    pub fn group_check_urls(&self) -> Vec<(String, String)> {
        self.group_check_urls
            .read()
            .iter()
            .map(|(g, u)| (g.clone(), u.clone()))
            .collect()
    }

    /// Install the member-tag → leaf resolver used by custom-URL probing
    /// (see the `group_check_urls` field docs).
    pub fn set_url_member_resolver(&self, resolver: Option<UrlMemberResolver>) {
        *self.url_member_resolver.write() = resolver;
    }

    /// Resolve custom-check members with their captured leaf identities.
    /// Empty when no resolver is installed.
    pub fn url_members_for(&self, group: &str) -> Vec<UrlProbeMember> {
        self.url_member_resolver
            .read()
            .as_ref()
            .map(|r| r(group))
            .unwrap_or_default()
    }

    /// Whether the member is alive for a custom check URL. The key is the
    /// member tag; members never probed default to alive.
    pub fn is_alive_for_url(&self, node_id: &str, url: &str) -> bool {
        self.url_states
            .read()
            .get(&(node_id.to_string(), url.to_string()))
            .map(|s| s.alive)
            .unwrap_or(true)
    }

    /// Whether any probe result has been recorded for (member tag, url).
    pub fn has_url_state(&self, node_id: &str, url: &str) -> bool {
        self.url_states
            .read()
            .contains_key(&(node_id.to_string(), url.to_string()))
    }

    /// Moving-average latency for (member tag, check_url) — the ranking
    /// metric for URLTest groups with a custom check URL.
    pub fn get_avg_latency_for_url(&self, node_id: &str, url: &str) -> Option<Duration> {
        let cols = self.url_collections.read();
        let coll = cols.get(&(node_id.to_string(), url.to_string()))?;
        let ma = coll.moving_average_duration();
        if ma > Duration::ZERO { Some(ma) } else { None }
    }

    /// Record a successful custom-URL probe (recovery hysteresis mirrors
    /// the global path: a dead node needs RECOVERY_SUCCESSES_NEEDED
    /// consecutive successes to revive).
    pub(crate) fn record_url_probe_success(&self, node_id: &str, url: &str, latency: Duration) {
        self.mark_url_probe_succeeded(node_id, url);
        let key = (node_id.to_string(), url.to_string());
        let coll = {
            let mut cols = self.url_collections.write();
            cols.entry(key)
                .or_insert_with(|| Arc::new(DialerCollection::new()))
                .clone()
        };
        if self.is_alive_for_url(node_id, url) {
            coll.mark_available(latency);
        }
    }

    /// Advance only the (tag, url) liveness state machine. A builtin leaf
    /// (direct/block) is exempt from URL probing, but a state that died
    /// under a previous non-builtin leaf must still recover once the member
    /// resolves to a builtin, or the tag stays filtered forever.
    pub(crate) fn mark_url_probe_succeeded(&self, node_id: &str, url: &str) {
        let key = (node_id.to_string(), url.to_string());
        {
            let mut states = self.url_states.write();
            let e = states.entry(key).or_insert_with(UrlProbeState::new);
            if e.alive {
                e.consecutive_failures = 0;
                e.consecutive_successes = 0;
                e.cooldown_until = Instant::now();
            } else {
                e.consecutive_successes += 1;
                e.consecutive_failures = 0;
                if e.consecutive_successes >= RECOVERY_SUCCESSES_NEEDED {
                    e.alive = true;
                    e.consecutive_successes = 0;
                    e.cooldown_until = Instant::now();
                }
            }
        }
        // A URL probe success refreshes the (tag, url) data selection
        // trusts (the average is fed when the pair is alive; a still-dead
        // pair is excluded either way), so the wake staleness ends.
        self.clear_url_stale(node_id, url);
    }

    /// Record a failed custom-URL probe: TCP-probe parity — three
    /// consecutive failures kill the node for this URL; backoff 5s→300s
    /// with no permanent stop.
    pub(crate) fn record_url_probe_failure(&self, node_id: &str, url: &str) {
        let key = (node_id.to_string(), url.to_string());
        {
            let mut states = self.url_states.write();
            let e = states.entry(key).or_insert_with(UrlProbeState::new);
            e.consecutive_successes = 0;
            e.consecutive_failures += 1;
            let backoff = probe_backoff(
                self.base_cooldown,
                self.max_cooldown,
                e.consecutive_failures,
            );
            e.cooldown_until = Instant::now() + backoff;
            if e.consecutive_failures >= probe_failure_threshold(ProbeDomain::Tcp) {
                e.alive = false;
            }
        }
        // Only a failure that flips the pair dead refreshes what selection
        // trusts; a single failure below the threshold leaves the old URL
        // latency in place, so the data stays stale.
        if !self.is_alive_for_url(node_id, url) {
            self.clear_url_stale(node_id, url);
        }
    }

    /// Whether a (node, url) probe is due (deep backoff still probes on
    /// the slow cadence, matching the global path).
    pub(super) fn should_probe_url(&self, node_id: &str, url: &str) -> bool {
        self.url_states
            .read()
            .get(&(node_id.to_string(), url.to_string()))
            .map(|s| Instant::now() >= s.cooldown_until)
            .unwrap_or(true)
    }

    #[cfg(test)]
    pub(crate) fn reset_url_backoff_for_recovery(&self, node_id: &str, url: &str) {
        if let Some(state) = self
            .url_states
            .write()
            .get_mut(&(node_id.to_string(), url.to_string()))
        {
            state.cooldown_until = Instant::now();
            if !state.alive {
                state.consecutive_successes = RECOVERY_SUCCESSES_NEEDED - 1;
            }
        }
    }

    /// Cached resolved IPs for a custom check URL, resolving on first use
    /// (same caching + literal-fallback semantics as the global check URL).
    pub(super) async fn check_ips_for_url(&self, url: &str) -> anyhow::Result<Vec<SocketAddr>> {
        if let Some(ips) = self.url_check_ips.read().get(url) {
            return Ok(ips.clone());
        }
        let ips = match honk_config::check::decode_health_http_target(url) {
            Ok(target) => {
                let port = target.port();
                match self.resolve_host(target.host(), port).await {
                    Ok(addrs) => Self::merge_check_addrs(addrs, url, port),
                    Err(error) => {
                        let literals = Self::merge_check_addrs(Vec::new(), url, port);
                        if literals.is_empty() {
                            return Err(error);
                        }
                        literals
                    }
                }
            }
            Err(_) => Self::merge_check_addrs(Vec::new(), url, 80),
        };
        self.url_check_ips
            .write()
            .insert(url.to_string(), ips.clone());
        Ok(ips)
    }

    /// Replace the whole idle-group table atomically.
    ///
    /// Entries for groups absent from `groups` are dropped, duplicate group
    /// names resolve last-definition-wins, and the node → groups index is
    /// rebuilt from the deduplicated entries. Activity timestamps survive for
    /// automatic groups that still exist.
    pub fn sync_idle_groups(&self, groups: &[IdleGroupRegistration]) {
        let mut idle = self.idle_groups.write();
        let generation = self.idle_generation.fetch_add(1, Ordering::AcqRel) + 1;
        let old_groups = std::mem::take(&mut idle.groups);
        idle.node_groups.clear();
        let mut new_groups = HashMap::with_capacity(groups.len());
        for registration in groups {
            let timeout = registration
                .idle_timeout
                .unwrap_or(DEFAULT_GROUP_IDLE_TIMEOUT);
            let last_active_ns = self.preserve_last_active_ns(
                old_groups.get(&registration.name),
                registration.kind,
                timeout,
            );
            let mut dedup_members = Vec::with_capacity(registration.members.len());
            for &member in &registration.members {
                if !dedup_members.contains(&member) {
                    dedup_members.push(member);
                }
            }
            let (tcp_recovery_members, udp_recovery_members) =
                if registration.kind == IdleGroupKind::Selector {
                    (Vec::new(), Vec::new())
                } else {
                    (
                        dedup_non_builtin(&registration.tcp_recovery_members),
                        dedup_non_builtin(&registration.udp_recovery_members),
                    )
                };
            new_groups.insert(
                registration.name.clone(),
                IdleGroupEntry {
                    members: dedup_members,
                    tcp_recovery_members,
                    udp_recovery_members,
                    activity: Arc::new(IdleActivitySlot::new(
                        generation,
                        registration.kind,
                        timeout,
                        last_active_ns,
                    )),
                },
            );
        }
        for (name, entry) in &new_groups {
            for &member in &entry.members {
                idle.node_groups
                    .entry(member)
                    .or_default()
                    .push(name.clone());
            }
        }
        idle.groups = new_groups;
    }

    /// Lock-free steady-state activity refresh for a cached [`IdleActivitySlot`].
    ///
    /// Returns `true` when `slot` matches the current idle-group generation and
    /// does not cross an idle→active wake boundary. Returns `false` when the
    /// caller must fall back to [`Self::mark_group_active_slot`].
    #[inline]
    pub fn try_touch_activity_slot(&self, slot: &IdleActivitySlot) -> bool {
        if slot.generation != self.idle_generation.load(Ordering::Acquire) {
            return false;
        }
        if slot.kind == IdleGroupKind::Selector || slot.timeout_ns == 0 {
            return true;
        }
        let now_ns = self.activity_now_ns(slot.use_coarse_clock);
        let prev = slot.last_active_ns.load(Ordering::Relaxed);
        if prev != 0 && now_ns.saturating_sub(prev) < slot.refresh_quantum_ns {
            return true;
        }
        if prev != 0 && now_ns.saturating_sub(prev) < slot.timeout_ns {
            match slot.last_active_ns.compare_exchange(
                prev,
                now_ns,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(cur) => return cur != 0 && now_ns.saturating_sub(cur) < slot.timeout_ns,
            }
        }
        false
    }

    /// Authoritative slow path for recording activity for an automatic group
    /// that also returns the group's [`IdleActivitySlot`] for subsequent
    /// lock-free refreshes via [`Self::try_touch_activity_slot`].
    ///
    /// When a suspended automatic group becomes active again, health checks
    /// resume and its direct members are probed immediately. `Selector` groups
    /// and groups with `idle_timeout == 0` stay idle without firing per-selection
    /// wake-up probes.
    pub fn mark_group_active_slot(&self, group: &str) -> Option<Arc<IdleActivitySlot>> {
        let idle = self.idle_groups.read();
        let entry = idle.groups.get(group)?;
        let slot = Arc::clone(&entry.activity);
        if slot.kind == IdleGroupKind::Selector || slot.timeout_ns == 0 {
            return Some(slot);
        }
        let now_ns = self.activity_now_ns(slot.use_coarse_clock);
        let prev = slot.last_active_ns.load(Ordering::Relaxed);
        if prev != 0 && now_ns.saturating_sub(prev) < slot.refresh_quantum_ns {
            return Some(slot);
        }
        let prev = slot.last_active_ns.fetch_max(now_ns, Ordering::AcqRel);
        if prev == 0 || now_ns.saturating_sub(prev) >= slot.timeout_ns {
            let members = entry.members.clone();
            // The group's probes were suspended until this wake, so members
            // whose probes were actually paused now carry stale health data
            // until a fresh probe lands. Only those members are marked: a
            // member held fixed by a Selector, or one whose other groups
            // are still active, never stopped probing, so its data is fresh.
            // The waking group itself is carved out: `fetch_max` above
            // already stamped it active.
            //
            // A group that was never active (`prev == 0`) is NOT marked:
            // its probes never ran while it was idle, so any data it holds
            // was recorded after sync (fresh) or does not exist at all —
            // and the no-measurements Cold branch already races that case.
            // Marking a never-active group would race a first selection
            // whose warm measurements are seconds old, which breaks the
            // TCP recovery and Score paths that dial the pick alone.
            // (One known gap: `preserve_last_active_ns` also collapses a
            // group that was already idle past its timeout at sync time to
            // `prev == 0`, so its first post-reload selection is not
            // marked; its probes resume on the wake and refresh the data
            // within a cycle. See plan §11.)
            let stale: Vec<Uuid> = if prev == 0 {
                Vec::new()
            } else {
                members
                    .iter()
                    .copied()
                    .filter(|id| {
                        *id != honk_config::config::BLOCK_NODE_ID
                            && *id != honk_config::config::DIRECT_NODE_ID
                            && !self.selected_nodes.read().contains(id)
                            && idle.node_groups.get(id).is_some_and(|groups| {
                                groups.iter().all(|name| {
                                    name == group
                                        || idle
                                            .groups
                                            .get(name)
                                            .is_some_and(|entry| self.is_entry_idle(entry))
                                })
                            })
                    })
                    .collect()
            };
            drop(idle);
            self.mark_stale(&stale);
            let custom_url = self.group_check_urls.read().get(group).cloned();
            let has_custom_url = if let Some(url) = custom_url {
                let now = Instant::now();
                let pinned = self.pinned_url_members_for(group);
                let mut stale_urls = Vec::new();
                {
                    let mut url_states = self.url_states.write();
                    for ((tag, state_url), state) in url_states.iter_mut() {
                        if state_url == &url {
                            state.cooldown_until = now;
                            // Pinned members keep URL probing while idle,
                            // so their data is fresh; the rest is stale
                            // until the wake probe lands. A never-active
                            // group (`prev == 0`) carries no aged URL data
                            // either — see the global marker above.
                            if prev != 0 && !pinned.contains(tag) {
                                stale_urls.push((tag.clone(), url.clone()));
                            }
                        }
                    }
                }
                self.mark_url_stale(&stale_urls);
                self.enqueue_url_group_wake(group);
                true
            } else {
                false
            };
            let wake_members: Vec<Uuid> = members
                .into_iter()
                .filter(|id| {
                    *id != honk_config::config::BLOCK_NODE_ID
                        && *id != honk_config::config::DIRECT_NODE_ID
                })
                .collect();
            if !wake_members.is_empty() || has_custom_url {
                tracing::debug!("Group '{}' active again — resuming member probes", group);
                for member in wake_members {
                    self.trigger_probe_node_only(member);
                }
            }
        }
        Some(slot)
    }

    /// Whether a registered group is currently idle. Never-active automatic
    /// groups, `Selector` groups, and groups with `idle_timeout == 0` count as
    /// idle. Unregistered groups are never idle.
    pub fn is_group_idle(&self, group: &str) -> bool {
        let idle = self.idle_groups.read();
        let Some(entry) = idle.groups.get(group) else {
            return false;
        };
        self.is_entry_idle(entry)
    }

    pub(super) fn is_groups_idle_for_node(&self, node_id: Uuid) -> bool {
        let idle = self.idle_groups.read();
        let Some(groups) = idle.node_groups.get(&node_id) else {
            return false;
        };
        if groups.is_empty() {
            return false;
        }
        groups.iter().all(|group| {
            idle.groups
                .get(group)
                .is_some_and(|entry| self.is_entry_idle(entry))
        })
    }

    /// Whether periodic probing of this node is suspended because every
    /// group it belongs to is idle. Nodes outside any group and nodes a
    /// group holds fixed (see [`Self::replace_selected_nodes`]) are never
    /// suspended.
    pub fn is_probe_suspended(&self, node_id: Uuid) -> bool {
        if self.selected_nodes.read().contains(&node_id) {
            return false;
        }
        self.is_groups_idle_for_node(node_id)
    }

    /// Whether this node's health data predates its group's idle wake: its
    /// probes were suspended until the wake and no fresh probe has landed
    /// yet. Selection races such members instead of trusting them alone.
    pub fn is_stale(&self, node_id: Uuid) -> bool {
        self.stale_members.read().contains_key(&node_id)
    }

    /// Same as [`Self::is_stale`] for custom-`check_url` groups, keyed by
    /// the member tag the URL probe state uses.
    pub fn is_url_stale(&self, tag: &str, url: &str) -> bool {
        self.stale_url_members
            .read()
            .contains_key(&(tag.to_string(), url.to_string()))
    }

    /// Mark members stale at their group's idle wake (see
    /// [`Self::mark_group_active_slot`]). Only members whose probes were
    /// actually suspended may be marked; the caller computes that set.
    pub(crate) fn mark_stale(&self, members: &[Uuid]) {
        if members.is_empty() {
            return;
        }
        let now = Instant::now();
        let mut stale = self.stale_members.write();
        for &member in members {
            stale.insert(member, now);
        }
    }

    /// Mark (tag, url) pairs stale at a custom-`check_url` group's wake.
    pub(crate) fn mark_url_stale(&self, pairs: &[(String, String)]) {
        if pairs.is_empty() {
            return;
        }
        let now = Instant::now();
        let mut stale = self.stale_url_members.write();
        for pair in pairs {
            stale.insert(pair.clone(), now);
        }
    }

    /// Clear a node's staleness once a fresh probe outcome has refreshed
    /// the data selection trusts (see `record_probe_latency_state` and
    /// `mark_unavailable_state`).
    pub(crate) fn clear_stale(&self, node_id: Uuid) {
        self.stale_members.write().remove(&node_id);
    }

    /// Clear a (tag, url) pair's staleness once a fresh URL probe outcome
    /// has refreshed its data.
    pub(crate) fn clear_url_stale(&self, tag: &str, url: &str) {
        self.stale_url_members
            .write()
            .remove(&(tag.to_string(), url.to_string()));
    }

    pub(super) fn needs_idle_recovery(&self, node_id: Uuid, domain: ProbeDomain) -> bool {
        if !matches!(domain, ProbeDomain::Tcp | ProbeDomain::DataUdp) {
            return false;
        }
        let idle = self.idle_groups.read();
        let Some(groups) = idle.node_groups.get(&node_id) else {
            return false;
        };
        let idx_v4 = alive_index(domain, IpVersion::V4);
        let states = self.states.read();
        groups.iter().any(|group| {
            let Some(entry) = idle.groups.get(group) else {
                return false;
            };
            if entry.activity.kind != IdleGroupKind::Automatic || !self.is_entry_idle(entry) {
                return false;
            }
            let recovery_members = match domain {
                ProbeDomain::Tcp => &entry.tcp_recovery_members,
                ProbeDomain::DataUdp => &entry.udp_recovery_members,
                ProbeDomain::DnsUdp => return false,
            };
            // TC allows V6→V4 fallback but never V4→V6, so an idle automatic
            // group's IPv4 datapath slot is closed iff no non-builtin reachable
            // recovery leaf is alive on `(domain, V4)`.
            recovery_members.contains(&node_id)
                && !recovery_members.iter().any(|member| {
                    // The fork has no route-health UDP fault table, so a
                    // recovery leaf is usable iff its (domain, V4) slot is alive.
                    states.get(member).is_none_or(|state| state[idx_v4].alive)
                })
        })
    }

    pub(super) fn pinned_url_members_for(&self, group: &str) -> HashSet<String> {
        self.pinned_url_members
            .read()
            .get(group)
            .cloned()
            .unwrap_or_default()
    }

    /// Atomically replace per-group pinned member tags for custom `check_url`
    /// probing and return newly added `(group, tag)` entries.
    pub fn replace_pinned_url_members(
        &self,
        pinned: HashMap<String, HashSet<String>>,
    ) -> Vec<(String, String)> {
        let mut current = self.pinned_url_members.write();
        let mut added = Vec::new();
        for (group, tags) in &pinned {
            let prev = current.get(group);
            for tag in tags {
                if prev.is_none_or(|existing| !existing.contains(tag)) {
                    added.push((group.clone(), tag.clone()));
                }
            }
        }
        *current = pinned;
        added
    }

    /// Clear custom-URL backoff and queue an immediate probe for newly pinned
    /// custom-`check_url` members.
    pub fn wake_pinned_url_members(&self, pins: &[(String, String)]) {
        if pins.is_empty() {
            return;
        }
        let now = Instant::now();
        for (group, tag) in pins {
            let Some(url) = self.group_check_urls.read().get(group).cloned() else {
                continue;
            };
            if let Some(state) = self.url_states.write().get_mut(&(tag.clone(), url)) {
                state.cooldown_until = now;
            }
            self.enqueue_url_group_wake(group);
        }
    }

    /// Atomically replace the fixed probe-node set and return newly added node
    /// IDs. The set holds a manual selection (Selector choice, an automatic
    /// group's pin) or a non-builtin node `final`; they keep periodic probing
    /// while idle, so a manually selected dead node can still recover.
    /// Holds only the leaf `selected_nodes` lock.
    pub fn replace_selected_nodes(&self, nodes: HashSet<Uuid>) -> Vec<Uuid> {
        let mut current = self.selected_nodes.write();
        let added = nodes
            .iter()
            .filter(|id| !current.contains(id))
            .copied()
            .collect();
        *current = nodes;
        added
    }

    /// Trigger immediate probes for any node in `nodes` whose owning idle
    /// groups are all currently idle.
    pub fn wake_idle_nodes(&self, nodes: &[Uuid]) {
        for &id in nodes {
            if self.is_groups_idle_for_node(id) {
                self.trigger_probe_node_only(id);
            }
        }
    }
}
