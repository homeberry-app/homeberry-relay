# Prism relay

Private experimental Rust transport. Independently buildable with Cargo; no Prism source, accounts, document engine, or private dependencies are required. Publication and license selection are pending review. `publish = false` deliberately prevents Cargo publication.

The relay connects an outbound household connector to an authorized client. Prism runs its existing pinned Hub TLS session inside this stream. The relay terminates the **outer** TLS connection but cannot decrypt that inner session. The household Hub remains responsible for authorization, encrypted storage and durable receipts.

## Build and verify

```sh
cargo build --release --locked
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --check
```

Tested on macOS with Rust 1.98. Linux deployment remains to be verified. Tests use disposable certificates and loopback sockets, including route isolation, invalid credentials, certificate validation, reconnect, rotation and bounded resource use.

## Run

One executable provides three operations:

```sh
prism-relay serve /absolute/path/server.json
prism-relay connect /absolute/path/connector.json
prism-relay bridge /absolute/path/client.json
```

Configuration files must be regular files, at most 64 KiB, with no group/other permissions on Unix (`chmod 600`). Unknown fields fail closed. Protect TLS private keys similarly. Resolve relative certificate paths from the process working directory; absolute paths are recommended.

Server configuration fields:

```json
{
  "listen": "0.0.0.0:8443",
  "certificate": "/etc/prism-relay/fullchain.pem",
  "private_key": "/etc/prism-relay/private-key.pem",
  "routes": [{
    "id": "<32 random bytes encoded as 64 lowercase hex characters>",
    "hub_token_sha256": "<SHA-256 of raw 32-byte Hub role token, lowercase hex>",
    "client_token_sha256": "<SHA-256 of separate raw 32-byte client role token, lowercase hex>"
  }]
}
```

Connector/client configuration fields:

```json
{
  "relay": "relay.example.com:8443",
  "server_name": "relay.example.com",
  "ca_certificate": null,
  "route": "<same route identifier>",
  "token": "<raw role token encoded as 64 lowercase hex characters>",
  "local": "127.0.0.1:8789"
}
```

Generate route IDs and each role token separately using a cryptographically secure random generator. Hash decoded token bytes, not their textual hex representation. Provision credentials through a trusted channel; never commit generated configuration. These tokens are separate from household encryption keys and Hub vault credentials.

`connect` maintains four outbound TLS connections and connects only to its configured loopback TCP target. It needs no inbound household firewall rule. `bridge` is a development client: `local` is its loopback listening address; it uses the client role token. Connect a TLS client with the **original Hub hostname and certificate validation** through that port. Neither operation may target/bind a non-loopback local address. `ca_certificate` optionally supplies trusted PEM roots for self-hosting; hostname and validity checks still apply. Otherwise public WebPKI roots are used.

Deploy behind TCP forwarding, not an HTTP reverse proxy. The process owns outer TLS; a load balancer must preserve TCP bytes. One instance holds all pending routes; multiple replicas require deliberate connection affinity and are not supported by this milestone. Restart to apply route/token changes; existing streams close. Credentials shared by clients are currently rotated as a group.

## Integration status

Prism's native adapter and fault runner consume this documented protocol without importing private source into this repository. Automatic route enrollment, credential distribution, app setup UI, service installation, Linux validation, AWS deployment and physical cellular acceptance remain unfinished. Do not expose the experimental service as a production offering yet.

Managed Terraform belongs in the separate private `prism-infra` repository. This service has no dependency on AWS or Prism-operated infrastructure.

See [protocol](PROTOCOL.md) and [security and release gates](SECURITY.md).
