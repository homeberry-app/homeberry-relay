# Transport protocol v1

Transport: TCP with server-authenticated TLS 1.3. Authenticate the outer service hostname and trust chain. Inside that connection send exactly 73 bytes:

| Offset | Length | Value |
| --- | --- | --- |
| 0 | 8 | ASCII `PRLY0001` |
| 8 | 1 | Role: Hub connector `1`, client `2` |
| 9 | 32 | Raw route identifier |
| 41 | 32 | Raw role capability |

The server selects the route and constant-time compares SHA-256 of the raw capability with the configured hash for that role. Invalid protocol, route, role or capability closes the connection without descriptive authentication responses.

Hub flow: server sends `1` (READY), queues the connector, then sends `2` (MATCHED) when a client arrives. Connector opens its fixed local target and replies `1` only after the TCP connection succeeds. The server then sends the client `1` (READY). Client flow: send preface, wait for READY; `3` means no connector available, followed by close. Any other response/EOF is failure. Waiting connectors must not send early data.

After READY, both sides carry unframed bidirectional bytes. Prism immediately performs its original inner TLS handshake against the household Hub, validating its saved hostname and exact certificate. A relay capability never replaces Hub authorization. No destination address comes from the client or relay.

Bounds: 64 configured routes, 128 sockets globally, 8 connectors per route including matched sessions, 64 TLS admissions per second globally, 5-second TLS/preface/match deadlines, 30-second pending connector wait, 60-second aggregate inactivity timeout, 600-second stream lifetime, 128 MiB per direction, 16 KiB forwarding buffers. Idle/lifetime/byte limits close the stream; callers must retain durable work until application-level acknowledgement. This transport provides no delivery receipt and does not replay writes.

Connector retries use capped exponential backoff with jitter, capped at 30 seconds. A completed matched stream replenishes promptly. Application reconnection must preserve request identities and storage-level idempotency. Server restart drops pending/active connections; household durable state is unaffected.

Future incompatible changes need a new magic/version. There is no HTTP, WebSocket, NAT traversal, discovery, provisioning or account protocol in v1.
