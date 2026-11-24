# Homeberry Relay

Open-source (MIT) standalone Rust transport for **Homeberry**. Independently buildable with Cargo — no Homeberry application source, accounts, document engine, or private dependencies are required.

The relay connects an outbound household **Homeberry Hub** connector to an authorized Homeberry client. Homeberry runs its existing pinned Hub TLS session inside this stream. The relay terminates the **outer** TLS connection but cannot decrypt the inner household session. The household Hub remains responsible for authorization, encrypted storage, and durable receipts.

> **Compatibility note:** The compiled binary and Cargo package retain the `prism-relay` identifier for wire and operational compatibility.

## Build and verify

```sh
cargo build --release --locked
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --check
```

Tests use disposable certificates and loopback sockets, covering route isolation, invalid credentials, certificate validation, reconnect, rotation, and bounded resource use.

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

Deploy behind TCP forwarding, not an HTTP reverse proxy. The process owns outer TLS; a load balancer must preserve TCP bytes. One instance holds all pending routes; multiple replicas require deliberate connection affinity. Restart to apply route/token changes; existing streams close.

## Protocol, security & infrastructure boundaries

- Managed Terraform belongs in the separate private [`homeberry-app/homeberry-infra`](https://github.com/homeberry-app/homeberry-infra) repository. This service has no dependency on AWS or Homeberry-operated infrastructure.
- See [`PROTOCOL.md`](PROTOCOL.md) and [`SECURITY.md`](SECURITY.md).
- Licensed under the [MIT License](LICENSE).
