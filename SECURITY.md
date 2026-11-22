# Security model and publication gates

This is an experimental private implementation, not a completed security audit. Report findings privately to the repository owner until a public disclosure contact is established.

The relay knows connecting IP addresses, route identifiers, role capabilities presented during outer TLS, traffic timing and byte counts. It can deny, delay, truncate or redirect traffic. It must never be trusted with household keys or treated as a synchronization authority. Prism's pinned inner Hub TLS detects substitution and protects Hub credentials and payloads from the relay. Other clients of this generic byte transport must supply their own authenticated end-to-end encryption.

Role credentials are random 256-bit capabilities. Server configuration stores only SHA-256 hashes. Client and connector role credentials must differ. A stolen client capability permits connection attempts and resource consumption, but does not authorize the inner Hub API. A stolen connector capability permits impersonating availability and denying service, but cannot satisfy the original Hub TLS pin. Rotation currently requires updating configuration and restarting; individual device revocation needs a later provisioning design.

No payloads are persisted. No addresses, routes, tokens or payloads are logged. Static configuration contains authentication state; TLS keys and peer capability files need owner-only access. The process does not zero all TLS/application memory or protect against host compromise. Fixed concurrency, byte, time and admission limits bound ordinary abuse but are not comprehensive distributed denial-of-service protection. Shared global limits can affect other routes. No unattended secret provisioning or renewal is implemented.

Before public release:

- Choose a license explicitly; no redistribution license has been granted by this repository yet.
- Review every tracked file and Git history for proprietary code, credentials and infrastructure details.
- Review dependency licenses and advisories; retain Cargo.lock and build with --locked.
- Obtain independent protocol/implementation review, including token provisioning, rotation, revocation and metadata expectations.
- Validate Linux packaging, unprivileged service confinement, TLS renewal, shutdown and operational monitoring.
- Prove actual native device-to-Hub sync across networks, offline recovery and service restarts.

Terraform, production environments and managed deployment secrets must remain in the separate private infrastructure repository. AWS secret storage does not replace device-local household keys. This milestone requires no cloud persistence of household content.
