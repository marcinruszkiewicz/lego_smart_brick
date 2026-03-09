defmodule SmartBrick.Ble do
  @moduledoc """
  Thin adapter over `RustlerBtleplug.Native` for BLE operations.

  Centralises NIF calls so the rest of the codebase doesn't import
  `RustlerBtleplug` directly, and provides a single place to swap
  implementations.

  ## Local NIF patch

  `rustler_btleplug` v0.0.17-alpha ships without `write_characteristic` and
  `read_characteristic` NIF bindings for central mode, even though the
  underlying btleplug Rust crate supports them. We've patched the dep
  locally (see `deps/rustler_btleplug/native/btleplug_client/src/peripheral.rs`
  and `deps/rustler_btleplug/lib/native.ex`).

  To rebuild after `mix deps.get`:

      RUSTLER_BTLEPLUG_BUILD=true mix deps.compile rustler_btleplug --force
  """

  require Logger

  @default_timeout 5_000

  @doc """
  Write `data` (binary) to the characteristic identified by `char_uuid`
  on the given peripheral reference.

  Uses ATT Write Request (with response) by default.
  """
  @spec write_characteristic(reference(), String.t(), binary(), keyword()) ::
          :ok | {:error, term()}
  def write_characteristic(peripheral_ref, char_uuid, data, opts \\ []) do
    with_response = Keyword.get(opts, :with_response, true)
    timeout = Keyword.get(opts, :timeout, @default_timeout)

    # Rustler decodes Vec<u8> from Erlang lists, not binaries
    data_list = :binary.bin_to_list(data)

    case RustlerBtleplug.Native.write_characteristic(
           peripheral_ref,
           char_uuid,
           data_list,
           with_response,
           timeout
         ) do
      {:error, reason} ->
        Logger.warning("[SmartBrick.Ble] write failed: #{inspect(reason)}")
        {:error, reason}

      _ref ->
        :ok
    end
  end

  @doc """
  Read from a characteristic. The result arrives asynchronously as a
  `{:btleplug_characteristic_value_changed, uuid, data}` message to the
  process that owns the peripheral ref.
  """
  @spec read_characteristic(reference(), String.t(), keyword()) :: :ok | {:error, term()}
  def read_characteristic(peripheral_ref, char_uuid, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, @default_timeout)

    case RustlerBtleplug.Native.read_characteristic(peripheral_ref, char_uuid, timeout) do
      {:error, reason} ->
        Logger.warning("[SmartBrick.Ble] read failed: #{inspect(reason)}")
        {:error, reason}

      _ref ->
        :ok
    end
  end
end
