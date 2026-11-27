Fixed
- XHTTP nodes now dial through a group detour instead of silently dropping it: a flow riding a group detour gets a private carrier session of its own, so it rides the named front and never shares a session with a flow on another path; a flow riding the node's own detour keeps the node's pooled carriers.
- XHTTP legs join the detour's shared deadline instead of resetting it: a carrier dial that runs out of the caller's remaining budget fails with the leg's hop tag, the same as every other transport.
