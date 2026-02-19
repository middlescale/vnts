# Copilot instructions for vnts

## Build and test
- Build: `cargo build`
- Build with web UI: `cargo build --features web`
- Tests (root crate): `cargo test`
- Single test: `cargo test <test_name>`
- Packet subcrate tests: `cd packet && cargo test` (single test: `cargo test <test_name>`)

## High-level architecture
- `src/main.rs` parses CLI args, loads RSA keys, sets up UDP/TCP listeners, then calls `core::start`.
- `core::start` wires the runtime: UDP/TCP servers, `PacketHandler`, cache/store, and optional Actix web admin (feature `web`).
- `core::service::PacketHandler` routes packets to client vs server handlers based on gateway flag in `protocol::NetPacket`.
- `src/protocol` defines the custom packet header/body format and parsing; `packet/` is a separate crate for L3/L4 parsing (IP/ARP/TCP/UDP).
- `proto/message.proto` is compiled to `src/proto/*` at build time; web static assets are bundled from `static/`.

## Key conventions
- **Generated code**: `src/proto/*` and `src/generated_serial_number.rs` are build outputs (see `build.rs`); edit `proto/message.proto` or build inputs instead of generated files.
- **Feature flags**: default `normal` uses AES-GCM; `ring-cipher` switches crypto backend; `web` enables Actix admin + static assets.
- **Runtime assets**: RSA keys live under `./key/`; logs default to `./log/` and can be configured via `./log/log4rs.yaml` (from README).
