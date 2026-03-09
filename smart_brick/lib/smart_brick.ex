defmodule SmartBrick do
  @moduledoc """
  Elixir BLE client for LEGO Smart Play bricks.

  Port of [node-smartplay](https://github.com/nathankellenicki/node-smartplay)
  using `rustler_btleplug` for macOS CoreBluetooth access.

  ## Quick start

      # Scan for nearby smart bricks
      {:ok, scanner} = SmartBrick.scan()

      # Wait for a discovery message
      receive do
        {:smart_brick_discovered, info} ->
          IO.puts("Found: \#{info.name} (\#{info.uuid})")

          # Connect
          {:ok, device} = SmartBrick.connect(scanner, info.uuid)

          # Wait for handshake
          receive do
            {:smart_brick_connected, device_info} ->
              IO.inspect(device_info, label: "Device")
          end

          # Read state
          SmartBrick.Device.battery(device)
          SmartBrick.Device.volume(device)

          # Control
          SmartBrick.Device.set_volume(device, :low)
          SmartBrick.Device.set_name(device, "MyBrick")

          # Disconnect
          SmartBrick.Device.disconnect(device)
      after
        10_000 -> IO.puts("No smart bricks found")
      end

      SmartBrick.Scanner.stop(scanner)

  ## Events

  The calling process receives these messages:

    * `{:smart_brick_discovered, %{uuid, name, rssi, services}}` — from scanner
    * `{:smart_brick_connected, %SmartBrick.Device.Info{}}` — handshake done
    * `{:smart_brick_battery, non_neg_integer()}` — battery changed
    * `{:smart_brick_charging, non_neg_integer()}` — charging state changed
    * `{:smart_brick_volume, non_neg_integer()}` — volume changed
    * `{:smart_brick_disconnect}` — connection lost

  ## Known limitations

  Auth (ECDSA P-256 via register 0x86) requires LEGO's backend and is
  intentionally skipped, same as node-smartplay.

  Requires building `rustler_btleplug` from source (OTP 28 NIF compat +
  local `write_characteristic`/`read_characteristic` patch). See README.
  """

  alias SmartBrick.Scanner
  alias SmartBrick.Device

  @doc """
  Start scanning for nearby LEGO Smart Play bricks.

  Returns `{:ok, scanner_pid}`. Discovery messages are sent to the calling
  process as `{:smart_brick_discovered, info}`.

  Options are forwarded to `SmartBrick.Scanner.start_link/1`.
  """
  @spec scan(keyword()) :: {:ok, pid()} | {:error, term()}
  def scan(opts \\ []) do
    opts = Keyword.put_new(opts, :caller, self())
    Scanner.start_link(opts)
  end

  @doc """
  Connect to a discovered smart brick by its UUID.

  `scanner` is the pid from `scan/1`. Returns `{:ok, device_pid}`.
  The caller receives `{:smart_brick_connected, info}` once the handshake
  completes.
  """
  @spec connect(pid(), String.t(), keyword()) :: {:ok, pid()} | {:error, term()}
  def connect(scanner, uuid, opts \\ []) do
    with {:ok, peripheral_ref} <- Scanner.find_peripheral(scanner, uuid) do
      opts =
        opts
        |> Keyword.put(:peripheral_ref, peripheral_ref)
        |> Keyword.put_new(:caller, self())

      Device.start_link(opts)
    end
  end

  @doc "Disconnect a connected device."
  @spec disconnect(pid()) :: :ok
  defdelegate disconnect(device), to: Device
end
