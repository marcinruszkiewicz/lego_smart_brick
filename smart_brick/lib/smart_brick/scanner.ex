defmodule SmartBrick.Scanner do
  @moduledoc """
  GenServer that scans for LEGO Smart Play bricks over BLE.

  Wraps `RustlerBtleplug.Native` and filters for peripherals advertising the
  FEF6 service with LEGO manufacturer data (company ID 0x0397).

  Discovered devices are forwarded to the caller as messages:

      {:smart_brick_discovered, %{uuid: String.t(), name: String.t()}}

  ## Usage

      {:ok, scanner} = SmartBrick.Scanner.start_link(caller: self())

      receive do
        {:smart_brick_discovered, info} ->
          IO.puts("Found: \#{info.name} (\#{info.uuid})")
      end

      SmartBrick.Scanner.stop(scanner)
  """

  use GenServer
  require Logger

  defstruct [:caller, :central_ref, :discovered, :scan_duration_ms]

  @default_scan_ms 5_000

  # -- Public API ----------------------------------------------------------

  @doc """
  Start the scanner. Options:

    * `:caller` - pid to receive discovery messages (default: `self()`)
    * `:scan_duration_ms` - how long the NIF scans per burst (default: 5000)
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts)
  end

  @doc "Stop the scanner and release BLE resources."
  def stop(pid) do
    GenServer.stop(pid, :normal)
  end

  @doc "Return the list of discovered peripherals so far."
  def discovered(pid) do
    GenServer.call(pid, :discovered)
  end

  @doc """
  Look up a peripheral ref by UUID. Returns the `RustlerBtleplug` peripheral
  resource that can be passed to `SmartBrick.Device.start_link/1`.
  """
  def find_peripheral(pid, uuid) do
    GenServer.call(pid, {:find_peripheral, uuid})
  end

  # -- GenServer callbacks -------------------------------------------------

  @impl true
  def init(opts) do
    caller = Keyword.get(opts, :caller, self())
    scan_ms = Keyword.get(opts, :scan_duration_ms, @default_scan_ms)

    case RustlerBtleplug.Native.create_central(self()) do
      {:error, reason} ->
        {:stop, {:create_central_failed, reason}}

      central_ref ->
        send(self(), :start_scan)

        {:ok,
         %__MODULE__{
           caller: caller,
           central_ref: central_ref,
           discovered: %{},
           scan_duration_ms: scan_ms
         }}
    end
  end

  @impl true
  def handle_info(:start_scan, state) do
    Logger.debug("[SmartBrick.Scanner] starting BLE scan")

    case RustlerBtleplug.Native.start_scan(state.central_ref, state.scan_duration_ms) do
      {:error, reason} ->
        Logger.warning("[SmartBrick.Scanner] start_scan failed: #{inspect(reason)}")
        {:noreply, state}

      _ref ->
        {:noreply, state}
    end
  end

  def handle_info({:btleplug_peripheral_discovered, uuid, info_map}, state) do
    handle_peripheral(uuid, info_map, state)
  end

  def handle_info({:btleplug_peripheral_updated, uuid, info_map}, state) do
    handle_peripheral(uuid, info_map, state)
  end

  def handle_info({:btleplug_scan_started, _msg}, state) do
    {:noreply, state}
  end

  def handle_info({:btleplug_scan_stopped, _msg}, state) do
    {:noreply, state}
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end

  @impl true
  def handle_call(:discovered, _from, state) do
    {:reply, Map.values(state.discovered), state}
  end

  def handle_call({:find_peripheral, uuid}, _from, state) do
    case RustlerBtleplug.Native.find_peripheral(state.central_ref, uuid) do
      {:error, reason} -> {:reply, {:error, reason}, state}
      peripheral_ref -> {:reply, {:ok, peripheral_ref}, state}
    end
  end

  @impl true
  def terminate(_reason, state) do
    if state.central_ref do
      RustlerBtleplug.Native.stop_scan(state.central_ref)
    end

    :ok
  end

  # -- Internal ------------------------------------------------------------

  @lego_company_id_str to_string(SmartBrick.Constants.lego_company_id())
  @fef6_service SmartBrick.Constants.fef6_service_uuid()

  defp handle_peripheral(uuid, info_map, state) do
    if Map.has_key?(state.discovered, uuid) do
      {:noreply, state}
    else
      if lego_brick?(info_map) do
        info = parse_peripheral_info(uuid, info_map)
        Logger.debug("[SmartBrick.Scanner] found LEGO brick: #{info.name || uuid}")
        new_discovered = Map.put(state.discovered, uuid, info)
        send(state.caller, {:smart_brick_discovered, info})
        {:noreply, %{state | discovered: new_discovered}}
      else
        {:noreply, state}
      end
    end
  end

  defp lego_brick?(info_map) do
    mfr = Map.get(info_map, "manufacturer_data", %{})
    services = Map.get(info_map, "services", [])

    Map.has_key?(mfr, @lego_company_id_str) or @fef6_service in services
  end

  defp parse_peripheral_info(uuid, info_map) do
    name_raw = Map.get(info_map, "local_name")
    name = if name_raw in [nil, "(unknown)"], do: nil, else: name_raw

    rssi_raw = Map.get(info_map, "rssi")

    rssi =
      case rssi_raw do
        "N/A" -> nil
        s when is_binary(s) -> String.to_integer(s)
        n when is_integer(n) -> n
        _ -> nil
      end

    services = Map.get(info_map, "services", [])

    %{uuid: uuid, name: name, rssi: rssi, services: services}
  end
end
