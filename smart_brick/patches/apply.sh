#!/bin/bash
# Re-apply local patches to rustler_btleplug after `mix deps.get`.
# Then rebuild: RUSTLER_BTLEPLUG_BUILD=true mix deps.compile rustler_btleplug --force
set -euo pipefail
cd "$(dirname "$0")/.."

PERIPHERAL_RS="deps/rustler_btleplug/native/btleplug_client/src/peripheral.rs"
NATIVE_EX="deps/rustler_btleplug/lib/native.ex"
CARGO_TOML="deps/rustler_btleplug/native/btleplug_client/Cargo.toml"

# --- Patch 1: Fix Cargo.toml for OTP 28 (cdylib + NIF 2.17) ---

if grep -q 'crate-type = \["dylib"' "$CARGO_TOML" 2>/dev/null; then
  echo "Patching $CARGO_TOML ..."
  # cdylib produces C-ABI .so with correct _nif_init symbol (dylib is Rust-ABI)
  sed -i '' 's/crate-type = \["dylib", "staticlib"\]/crate-type = ["cdylib"]/' "$CARGO_TOML"
  # OTP 28 requires NIF 2.17
  sed -i '' 's/default = \["nif_version_2_15"\]/default = ["nif_version_2_17"]/' "$CARGO_TOML"
  # Update rustler dep features to match
  sed -i '' 's/features = \["staticlib", "derive", "nif_version_2_15"\]/features = ["derive", "nif_version_2_17"]/' "$CARGO_TOML"
  echo "  Done."
else
  echo "$CARGO_TOML already patched (or crate-type not found)."
fi

# --- Patch 2: Fix connect() to update notification target pid ---
# The PeripheralRef stores the pid from find_peripheral (Scanner process).
# The Device GenServer calls connect(), so we update the pid to the caller
# so that subscribe notifications go to the Device, not the Scanner.

if ! grep -q 'Update notification target to the caller' "$PERIPHERAL_RS" 2>/dev/null; then
  echo "Patching $PERIPHERAL_RS (connect pid fix) ..."
  sed -i '' '/let env_pid = env.pid();/{
    N
    s/let env_pid = env.pid();\n/let env_pid = env.pid();\
\
    \/\/ Update notification target to the caller (e.g. Device GenServer)\
    \{\
        let mut state_guard = peripheral_arc.lock().unwrap();\
        state_guard.pid = env_pid;\
    \}\
\
/
  }' "$PERIPHERAL_RS"
  echo "  Done."
else
  echo "$PERIPHERAL_RS connect pid patch already applied."
fi

# --- Patch 3: Add write_characteristic and read_characteristic NIFs to Rust ---

if ! grep -q 'fn write_characteristic' "$PERIPHERAL_RS" 2>/dev/null; then
  echo "Patching $PERIPHERAL_RS ..."

  # Add WriteType import
  sed -i '' 's/use btleplug::api::{CentralEvent, CharPropFlags, Peripheral as ApiPeripheral};/use btleplug::api::{CentralEvent, CharPropFlags, Peripheral as ApiPeripheral, WriteType};/' "$PERIPHERAL_RS"

  # Append write_characteristic and read_characteristic functions
  cat >> "$PERIPHERAL_RS" << 'RUST_EOF'

#[rustler::nif]
pub fn write_characteristic(
    env: Env,
    resource: ResourceArc<PeripheralRef>,
    characteristic_uuid: String,
    data: Vec<u8>,
    write_with_response: bool,
    timeout_ms: u64,
) -> Result<ResourceArc<PeripheralRef>, RustlerError> {
    let peripheral_arc = resource.0.clone();

    RUNTIME.spawn(async move {
        let (peripheral, state, _pid) = {
            let state_guard = peripheral_arc.lock().unwrap();
            (
                state_guard.peripheral.clone(),
                state_guard.state,
                state_guard.pid,
            )
        };

        if state != PeripheralStateEnum::ServicesDiscovered
            && state != PeripheralStateEnum::Connected
        {
            log::warn!("Cannot write: not connected or services not discovered (state: {:?})", state);
            return;
        }

        let characteristics = peripheral.characteristics();
        let characteristic = characteristics
            .iter()
            .find(|c| c.uuid.to_string().to_lowercase() == characteristic_uuid.to_lowercase())
            .cloned();

        match characteristic {
            Some(char) => {
                let write_type = if write_with_response {
                    WriteType::WithResponse
                } else {
                    WriteType::WithoutResponse
                };

                match tokio::time::timeout(
                    tokio::time::Duration::from_millis(timeout_ms),
                    peripheral.write(&char, &data, write_type),
                )
                .await
                {
                    Ok(Ok(_)) => log::info!("Write succeeded for {:?}", char.uuid),
                    Ok(Err(e)) => log::warn!("Write failed for {:?}: {:?}", char.uuid, e),
                    Err(_) => log::warn!("Write timed out for {:?}", char.uuid),
                }
            }
            None => log::warn!(
                "Characteristic {} not found for write",
                characteristic_uuid
            ),
        }
    });

    Ok(resource)
}

#[rustler::nif]
pub fn read_characteristic(
    env: Env,
    resource: ResourceArc<PeripheralRef>,
    characteristic_uuid: String,
    timeout_ms: u64,
) -> Result<ResourceArc<PeripheralRef>, RustlerError> {
    let peripheral_arc = resource.0.clone();

    RUNTIME.spawn(async move {
        let (peripheral, state, pid) = {
            let state_guard = peripheral_arc.lock().unwrap();
            (
                state_guard.peripheral.clone(),
                state_guard.state,
                state_guard.pid,
            )
        };

        if state != PeripheralStateEnum::ServicesDiscovered
            && state != PeripheralStateEnum::Connected
        {
            log::warn!("Cannot read: not connected or services not discovered (state: {:?})", state);
            return;
        }

        let characteristics = peripheral.characteristics();
        let characteristic = characteristics
            .iter()
            .find(|c| c.uuid.to_string().to_lowercase() == characteristic_uuid.to_lowercase())
            .cloned();

        match characteristic {
            Some(char) => {
                match tokio::time::timeout(
                    tokio::time::Duration::from_millis(timeout_ms),
                    peripheral.read(&char),
                )
                .await
                {
                    Ok(Ok(data)) => {
                        let mut msg_env = OwnedEnv::new();
                        msg_env
                            .send_and_clear(&pid, |env| {
                                (
                                    crate::atoms::btleplug_characteristic_value_changed(),
                                    char.uuid.to_string(),
                                    data.clone(),
                                )
                                    .encode(env)
                            })
                            .ok();
                    }
                    Ok(Err(e)) => log::warn!("Read failed for {:?}: {:?}", char.uuid, e),
                    Err(_) => log::warn!("Read timed out for {:?}", char.uuid),
                }
            }
            None => log::warn!(
                "Characteristic {} not found for read",
                characteristic_uuid
            ),
        }
    });

    Ok(resource)
}
RUST_EOF
  echo "  Done."
else
  echo "$PERIPHERAL_RS already patched."
fi

# If peripheral was already patched, upgrade UUID comparison to case-insensitive (for FTC/FTD on macOS)
if grep -q 'c.uuid.to_string() == characteristic_uuid' "$PERIPHERAL_RS" 2>/dev/null; then
  echo "Updating $PERIPHERAL_RS for case-insensitive UUID match..."
  sed -i '' 's/c\.uuid\.to_string() == characteristic_uuid/c.uuid.to_string().to_lowercase() == characteristic_uuid.to_lowercase()/g' "$PERIPHERAL_RS"
  echo "  Done."
fi

# --- Patch 4: Add Elixir declarations for write/read ---

if ! grep -q 'def write_characteristic' "$NATIVE_EX" 2>/dev/null; then
  echo "Patching $NATIVE_EX ..."

  # Insert before "## Adapter State Queries"
  sed -i '' '/## Adapter State Queries/i\
\
  ## Characteristic Read/Write (Central mode)\
  @spec write_characteristic(peripheral(), uuid(), binary(), boolean(), number()) ::\
          {:ok, peripheral()} | {:error, term()}\
  def write_characteristic(_peripheral, _characteristic_uuid, _data, _with_response \\\\ true, _timeout \\\\ @default_timeout),\
    do: error()\
\
  @spec read_characteristic(peripheral(), uuid(), number()) ::\
          {:ok, peripheral()} | {:error, term()}\
  def read_characteristic(_peripheral, _characteristic_uuid, _timeout \\\\ @default_timeout),\
    do: error()\
' "$NATIVE_EX"
  echo "  Done."
else
  echo "$NATIVE_EX already patched."
fi

echo ""
echo "Patches applied. Now run:"
echo "  RUSTLER_BTLEPLUG_BUILD=true mix deps.compile rustler_btleplug --force"
