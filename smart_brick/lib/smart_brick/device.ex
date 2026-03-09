defmodule SmartBrick.Device do
  @moduledoc """
  GenServer managing a single LEGO Smart Brick BLE connection.

  Handles the full lifecycle: connect → subscribe characteristics → handshake
  (read identity registers) → keepalive polling loop → disconnect.

  ## Events

  The following messages are sent to the `:caller` process:

    * `{:smart_brick_connected, %SmartBrick.Device.Info{}}` — handshake complete
    * `{:smart_brick_battery, non_neg_integer()}` — battery level changed
    * `{:smart_brick_charging, non_neg_integer()}` — charging state changed
    * `{:smart_brick_disconnect}` — connection lost

  ## Usage

      {:ok, device} = SmartBrick.Device.start_link(
        peripheral_ref: ref,
        caller: self()
      )

      SmartBrick.Device.info(device)
      SmartBrick.Device.set_volume(device, :medium)
      SmartBrick.Device.disconnect(device)
  """

  use GenServer
  require Logger

  alias SmartBrick.Constants
  alias SmartBrick.Protocol

  # -- Public structs ------------------------------------------------------

  defmodule Info do
    @moduledoc "Device identity populated during the handshake."
    defstruct [:uuid, :name, :model, :firmware, :mac]

    @type t :: %__MODULE__{
            uuid: String.t(),
            name: String.t(),
            model: String.t(),
            firmware: String.t(),
            mac: String.t()
          }
  end

  defmodule State do
    @moduledoc false
    defstruct [
      :caller,
      :peripheral_ref,
      :poll_timer,
      :info,
      battery: 0,
      volume: 0,
      charging_state: 0,
      connected: false,
      pending: %{}
    ]
  end

  # -- Public API ----------------------------------------------------------

  @doc """
  Start a device connection. Required options:

    * `:peripheral_ref` — the NIF peripheral resource from the scanner
    * `:caller` — pid to receive event messages (default: `self()`)
  """
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @doc "Return the device identity info."
  @spec info(GenServer.server()) :: Info.t()
  def info(pid), do: GenServer.call(pid, :info)

  @doc "Return the current battery level (0–100)."
  @spec battery(GenServer.server()) :: non_neg_integer()
  def battery(pid), do: GenServer.call(pid, :battery)

  @doc "Return the current volume level."
  @spec volume(GenServer.server()) :: non_neg_integer()
  def volume(pid), do: GenServer.call(pid, :volume)

  @doc """
  Set the volume. Accepts `:high` (100), `:medium` (40), or `:low` (10).
  """
  @spec set_volume(GenServer.server(), :high | :medium | :low) :: :ok | {:error, term()}
  def set_volume(pid, level) when level in [:high, :medium, :low] do
    GenServer.call(pid, {:set_volume, level})
  end

  @doc "Set the device name (max 12 bytes UTF-8)."
  @spec set_name(GenServer.server(), String.t()) :: :ok | {:error, term()}
  def set_name(pid, name) when is_binary(name) do
    GenServer.call(pid, {:set_name, name})
  end

  @doc "Read a raw register and return the response data."
  @spec read_register(GenServer.server(), atom()) :: {:ok, binary()} | {:error, term()}
  def read_register(pid, register) when is_atom(register) do
    GenServer.call(pid, {:read_register, register}, Constants.default_timeout_ms() + 2_000)
  end

  @doc "Disconnect from the device."
  @spec disconnect(GenServer.server()) :: :ok
  def disconnect(pid) do
    GenServer.cast(pid, :disconnect)
  end

  # -- GenServer callbacks -------------------------------------------------

  @impl true
  def init(opts) do
    peripheral_ref = Keyword.fetch!(opts, :peripheral_ref)
    caller = Keyword.get(opts, :caller, self())

    state = %State{
      caller: caller,
      peripheral_ref: peripheral_ref,
      info: %Info{}
    }

    {:ok, state, {:continue, :connect}}
  end

  @impl true
  def handle_continue(:connect, state) do
    case do_connect(state) do
      {:ok, state} ->
        {:noreply, state, {:continue, :handshake}}

      {:error, reason} ->
        Logger.error("[SmartBrick.Device] connection failed: #{inspect(reason)}")
        {:stop, {:connection_failed, reason}, state}
    end
  end

  def handle_continue(:handshake, state) do
    case do_handshake(state) do
      {:ok, state} ->
        send(state.caller, {:smart_brick_connected, state.info})
        timer = :timer.send_interval(Constants.poll_interval_ms(), self(), :poll)
        {:noreply, %{state | connected: true, poll_timer: timer}}

      {:error, reason} ->
        Logger.error("[SmartBrick.Device] handshake failed: #{inspect(reason)}")
        {:stop, {:handshake_failed, reason}, state}
    end
  end

  @impl true
  def handle_call(:info, _from, state) do
    {:reply, state.info, state}
  end

  def handle_call(:battery, _from, state) do
    {:reply, state.battery, state}
  end

  def handle_call(:volume, _from, state) do
    {:reply, state.volume, state}
  end

  def handle_call({:set_volume, level}, _from, state) do
    with {:ok, upgrade_data} <- send_read(state, :upgrade_state),
         0 <- Protocol.parse_upgrade_state(upgrade_data),
         payload = <<Constants.volume_level(level)>>,
         :ok <- send_write_no_response(state, :user_volume, payload),
         {:ok, vol_data} <- send_read(state, :user_volume) do
      new_vol = Protocol.parse_volume(vol_data)

      if new_vol != state.volume do
        send(state.caller, {:smart_brick_volume, new_vol})
      end

      {:reply, :ok, %{state | volume: new_vol}}
    else
      upgrade when is_integer(upgrade) ->
        {:reply, {:error, :device_busy}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:set_name, name}, _from, state) do
    payload = String.slice(name, 0, 12)
    send_write_no_response(state, :hub_local_name, payload)

    case send_read(state, :hub_local_name) do
      {:ok, data} ->
        new_name = Protocol.parse_hub_local_name(data)
        {:reply, :ok, put_in(state.info.name, new_name)}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:read_register, register}, from, state) do
    cmd = Protocol.encode_read(register)
    key = Protocol.register_key(register)

    timer_ref =
      Process.send_after(self(), {:request_timeout, key}, Constants.default_timeout_ms())

    pending =
      Map.update(state.pending, key, [{from, timer_ref}], &[{from, timer_ref} | &1])

    write_to_control_point(state.peripheral_ref, cmd)
    {:noreply, %{state | pending: pending}}
  end

  @impl true
  def handle_cast(:disconnect, state) do
    cancel_poll(state.poll_timer)
    RustlerBtleplug.Native.disconnect(state.peripheral_ref)
    {:stop, :normal, %{state | connected: false, poll_timer: nil}}
  end

  @impl true
  def handle_info(:poll, state) do
    do_poll(state)
    {:noreply, state}
  end

  def handle_info({:btleplug_characteristic_value_changed, _char_uuid, raw}, state)
      when is_binary(raw) do
    handle_characteristic_data(raw, state)
  end

  def handle_info({:btleplug_characteristic_value_changed, _char_uuid, raw_list}, state)
      when is_list(raw_list) do
    handle_characteristic_data(:erlang.list_to_binary(raw_list), state)
  end

  def handle_info({:btleplug_peripheral_disconnected, _uuid}, state) do
    Logger.info("[SmartBrick.Device] peripheral disconnected")
    send(state.caller, {:smart_brick_disconnect})
    cancel_poll(state.poll_timer)
    {:stop, :normal, %{state | connected: false, poll_timer: nil}}
  end

  def handle_info({:request_timeout, key}, state) do
    case Map.pop(state.pending, key) do
      {nil, _} ->
        {:noreply, state}

      {entries, rest} ->
        Enum.each(entries, fn {from, _tref} ->
          GenServer.reply(from, {:error, :timeout})
        end)

        {:noreply, %{state | pending: rest}}
    end
  end

  def handle_info(msg, state) do
    Logger.debug("[SmartBrick.Device] unhandled: #{inspect(msg)}")
    {:noreply, state}
  end

  @impl true
  def terminate(_reason, state) do
    cancel_poll(state.poll_timer)

    if state.connected do
      RustlerBtleplug.Native.disconnect(state.peripheral_ref)
    end

    :ok
  end

  # -- Connection ----------------------------------------------------------

  defp do_connect(state) do
    ref = state.peripheral_ref

    case RustlerBtleplug.Native.connect(ref, 10_000) do
      {:error, reason} ->
        {:error, reason}

      _ref ->
        # NIF connect is async; wait for BLE connection + service discovery
        Logger.debug("[SmartBrick.Device] waiting for BLE connection...")
        Process.sleep(5_000)

        Logger.debug("[SmartBrick.Device] subscribing to characteristics...")
        subscribe_characteristics(ref)

        # NIF subscribe is async (each task sleeps 2s + subscribes);
        # wait for all subscriptions to become active
        Logger.debug("[SmartBrick.Device] waiting for subscriptions to activate...")
        Process.sleep(5_000)

        {:ok, state}
    end
  end

  defp subscribe_characteristics(peripheral_ref) do
    for uuid <- Constants.subscription_uuids() do
      case RustlerBtleplug.Native.subscribe(peripheral_ref, uuid, 10_000) do
        {:error, reason} ->
          Logger.warning(
            "[SmartBrick.Device] subscribe #{uuid} failed: #{inspect(reason)}"
          )

        _ref ->
          Logger.debug("[SmartBrick.Device] subscribe requested: #{uuid}")
      end

      Process.sleep(200)
    end
  end

  # -- Handshake -----------------------------------------------------------

  defp do_handshake(state) do
    with {:ok, model_data} <- send_read(state, :device_model),
         {:ok, fw_data} <- send_read(state, :firmware_revision),
         {:ok, vol_data} <- send_read(state, :user_volume),
         {:ok, mac_data} <- send_read(state, :primary_mac_address),
         {:ok, name_data} <- send_read(state, :hub_local_name),
         {:ok, bat_data} <- send_read(state, :battery_level),
         :ok <- send_write_no_response(state, :ux_signal, Constants.keepalive_data()),
         {:ok, _mtu_data} <- send_read(state, :current_att_mtu) do
      info = %Info{
        uuid: (state.info && state.info.uuid) || "",
        model: Protocol.parse_device_model(model_data),
        firmware: Protocol.parse_firmware_revision(fw_data),
        mac: Protocol.parse_mac_address(mac_data),
        name: Protocol.parse_hub_local_name(name_data)
      }

      volume = Protocol.parse_volume(vol_data)
      battery = Protocol.parse_battery_level(bat_data)

      Logger.info(
        "[SmartBrick.Device] connected: #{info.name} (#{info.model}) fw=#{info.firmware} mac=#{info.mac} bat=#{battery}%"
      )

      {:ok, %{state | info: info, volume: volume, battery: battery}}
    end
  end

  # -- Polling -------------------------------------------------------------

  defp do_poll(state) do
    send_write_no_response(state, :ux_signal, Constants.keepalive_data())

    # Fire read commands; responses arrive as notifications and are
    # handled by handle_characteristic_data/handle_unsolicited
    write_to_control_point(state.peripheral_ref, Protocol.encode_read(:battery_level))
    write_to_control_point(state.peripheral_ref, Protocol.encode_read(:charging_state))
  end

  # -- Register I/O --------------------------------------------------------

  # Synchronous register read: write the read command, then wait for the
  # matching response notification. Uses a simple receive-based approach
  # for the handshake (called from the GenServer process during init).
  defp send_read(state, register) do
    cmd = Protocol.encode_read(register)
    Logger.debug("[SmartBrick.Device] reading register #{register}...")
    write_to_control_point(state.peripheral_ref, cmd)
    await_register_response(register, Constants.default_timeout_ms())
  end

  defp await_register_response(register, timeout) do
    deadline = System.monotonic_time(:millisecond) + timeout

    receive do
      {:btleplug_characteristic_value_changed, _uuid, raw} ->
        data = if is_list(raw), do: :erlang.list_to_binary(raw), else: raw

        case Protocol.decode_response(data) do
          {:ok, %{register: ^register, data: payload}} ->
            Logger.debug("[SmartBrick.Device] got #{register}: #{byte_size(payload)} bytes")
            {:ok, payload}

          {:ok, %{register: other}} ->
            remaining = deadline - System.monotonic_time(:millisecond)

            if remaining > 0 do
              Logger.debug(
                "[SmartBrick.Device] discarding stale #{inspect(other)} while waiting for #{register}"
              )

              await_register_response(register, remaining)
            else
              {:error, :timeout}
            end

          :error ->
            remaining = deadline - System.monotonic_time(:millisecond)

            if remaining > 0 do
              await_register_response(register, remaining)
            else
              {:error, :decode_failed}
            end
        end
    after
      max(timeout, 0) ->
        Logger.warning("[SmartBrick.Device] timeout waiting for #{register}")
        {:error, :timeout}
    end
  end

  defp send_write_no_response(state, register, data) do
    cmd = Protocol.encode_write(register, data)
    write_to_control_point(state.peripheral_ref, cmd)
    :ok
  end

  # -- BLE write -----------------------------------------------------------

  defp write_to_control_point(peripheral_ref, data) do
    SmartBrick.Ble.write_characteristic(
      peripheral_ref,
      Constants.control_point_uuid(),
      data,
      with_response: true
    )
  end

  defp cancel_poll(nil), do: :ok

  defp cancel_poll({:ok, tref}) do
    :timer.cancel(tref)
    :ok
  end

  defp cancel_poll(tref) when is_reference(tref) do
    Process.cancel_timer(tref)
    :ok
  end

  defp cancel_poll(_), do: :ok

  # -- Incoming data -------------------------------------------------------

  defp handle_characteristic_data(raw, state) do
    case Protocol.decode_response(raw) do
      {:ok, %{register: register, data: data}} ->
        key = Protocol.register_key(register)

        case Map.pop(state.pending, key) do
          {nil, _} ->
            new_state = handle_unsolicited(register, data, state)
            {:noreply, new_state}

          {[{from, tref} | rest], pending} ->
            Process.cancel_timer(tref)
            GenServer.reply(from, {:ok, data})
            pending = if rest == [], do: pending, else: Map.put(pending, key, rest)
            {:noreply, %{state | pending: pending}}
        end

      :error ->
        Logger.debug(
          "[SmartBrick.Device] non-response notification: #{Base.encode16(raw)}"
        )

        {:noreply, state}
    end
  end

  defp handle_unsolicited(register, data, state) do
    case register do
      :battery_level ->
        level = Protocol.parse_battery_level(data)

        if level != state.battery do
          send(state.caller, {:smart_brick_battery, level})
        end

        %{state | battery: level}

      :charging_state ->
        cs = Protocol.parse_charging_state(data)

        if cs != state.charging_state do
          send(state.caller, {:smart_brick_charging, cs})
        end

        %{state | charging_state: cs}

      _ ->
        state
    end
  end
end
