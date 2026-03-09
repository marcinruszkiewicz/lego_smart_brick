# SmartBrick

Elixir BLE client for LEGO Smart Play bricks. Port of [node-smartplay](https://github.com/nathankellenicki/node-smartplay) using `rustler_btleplug` for macOS CoreBluetooth access.

## Setup

Requires Elixir 1.18+ and Rust (for building the BLE NIF from source -- needed for OTP 28+ and our local `write_characteristic` patch).

```bash
mix deps.get
RUSTLER_BTLEPLUG_BUILD=true mix compile
```

If you use direnv, the included `.envrc` sets the build flag automatically.

## Usage

```elixir
RUST_LOG=error mix run -e "SmartBrick.CLI.run()"
```

## Local NIF patches

`rustler_btleplug` v0.0.17-alpha needs three patches for our use case:

1. **Cargo.toml**: Changed `crate-type` from `dylib` to `cdylib` (C-ABI for correct `_nif_init` symbol), bumped NIF version from 2.15 to 2.17 (OTP 28).
2. **peripheral.rs**: Added `write_characteristic` and `read_characteristic` Rust NIF functions (btleplug supports them, the Elixir bindings were just missing).
3. **native.ex**: Added matching Elixir declarations for the new NIF functions.

After `mix deps.get` (which overwrites deps), re-apply and rebuild:

```bash
./patches/apply.sh
RUSTLER_BTLEPLUG_BUILD=true mix deps.compile rustler_btleplug --force
```

## Known limitations

- **Auth skipped**: ECDSA P-256 signing (register 0x86) requires LEGO's backend server and is intentionally not implemented, same as node-smartplay.
- **Rust required**: Must build `rustler_btleplug` from source due to the local patches and OTP 28 NIF compatibility.
