Fixed
- Load-time detour cycle rejection also follows a group's direct member nodes, so a cycle closed through a member (group → member → that member's detour → back to the group) is rejected at load instead of failing at dial time on the 4-hop cap; a group reached through a nested group or a fallback is expanded the same way as one named by a detour.
