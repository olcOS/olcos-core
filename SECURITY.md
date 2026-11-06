# Security policy

## Report privately

Do not open a public issue or pull request with an unpatched vulnerability,
exploit details or secrets. Use GitHub's
[private vulnerability reporting](https://github.com/olcOS/olcos-core/security/advisories/new)
for this repository (or the one in [olcOS/olcos](https://github.com/olcOS/olcos/security/advisories/new)
if you are not sure where the problem is).

Include the affected olcos-core tag or commit, the app and its version if one
is involved, the impact, and minimal steps with test data. Leave out real IP
addresses, room IDs, keys and connection links. Do not test against other
people's devices, accounts or servers.

## Scope

- the server agent (`mobile/agent`): authentication, TLS, invites, the
  scripts it runs;
- the server scripts (`server/`): command construction, what they expose on
  the network, how they handle secrets;
- the tunnel stack and bonding (`mobile/tunstack`, `mobile/bond`): leaks
  around the tunnel, parsing of untrusted input;
- the profile parsers (`profile/`) and the Xray engine (`engine/xray`);
- the olcOS changes to `olcrtc/` (the files marked `Changed by olcOS`).

A defect in upstream olcrtc code goes to
[ghostlane-project/olcrtc](https://github.com/ghostlane-project/olcrtc)
through its own security policy (`olcrtc/SECURITY.md`); if you are unsure,
report it here first. App-side issues (the iOS and Android code) belong to
the app repositories' policies.

No response deadline or bounty is promised.
