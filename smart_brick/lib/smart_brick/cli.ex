defmodule SmartBrick.CLI do
  @moduledoc """
  Interactive CLI for scanning, connecting to, and controlling LEGO Smart
  Play bricks over BLE.

  Run with: mix run -e "SmartBrick.CLI.run()"
  """

  alias SmartBrick.Device

  @scan_wait_ms 10_000
  @connect_timeout_ms 30_000

  # -- Entry point ---------------------------------------------------------

  def run do
    System.put_env("RUST_LOG", System.get_env("RUST_LOG") || "error")
    IO.puts("\n=== LEGO Smart Brick CLI ===\n")
    scan_phase()
  end

  # -- Scan phase ----------------------------------------------------------

  defp scan_phase do
    IO.puts("Scanning for LEGO Smart Bricks...")

    case SmartBrick.scan() do
      {:ok, scanner} ->
        devices = collect_discoveries(scanner, @scan_wait_ms)
        scan_prompt(scanner, devices)

      {:error, reason} ->
        IO.puts("Failed to start scanner: #{inspect(reason)}")
    end
  end

  defp collect_discoveries(scanner, remaining) when remaining <= 0 do
    SmartBrick.Scanner.discovered(scanner)
  end

  defp collect_discoveries(scanner, remaining) do
    step = min(remaining, 500)

    receive do
      {:smart_brick_discovered, info} ->
        label = info.name || info.uuid
        rssi = if info.rssi, do: " (rssi: #{info.rssi})", else: ""
        IO.puts("  Found: #{label}#{rssi}")
        collect_discoveries(scanner, remaining - step)
    after
      step ->
        collect_discoveries(scanner, remaining - step)
    end
  end

  defp scan_prompt(scanner, devices) do
    if devices == [] do
      IO.puts("\nNo smart bricks found.")

      case prompt("r to rescan, q to quit: ") do
        "r" ->
          SmartBrick.Scanner.stop(scanner)
          scan_phase()

        _ ->
          SmartBrick.Scanner.stop(scanner)
          IO.puts("Bye.")
      end
    else
      IO.puts("\n  Available devices:\n")

      devices
      |> Enum.with_index(1)
      |> Enum.each(fn {dev, idx} ->
        label = dev.name || dev.uuid
        rssi = if dev.rssi, do: "  rssi: #{dev.rssi}", else: ""
        IO.puts("    [#{idx}] #{label}#{rssi}")
      end)

      IO.puts("")

      case prompt("Enter number to connect, r to rescan, q to quit: ") do
        "r" ->
          SmartBrick.Scanner.stop(scanner)
          scan_phase()

        "q" ->
          SmartBrick.Scanner.stop(scanner)
          IO.puts("Bye.")

        input ->
          case Integer.parse(input) do
            {n, _} when n >= 1 and n <= length(devices) ->
              dev = Enum.at(devices, n - 1)
              connect_phase(scanner, dev)

            _ ->
              IO.puts("Invalid choice.")
              scan_prompt(scanner, devices)
          end
      end
    end
  end

  # -- Connect phase -------------------------------------------------------

  defp connect_phase(scanner, dev) do
    label = dev.name || dev.uuid
    IO.puts("\nConnecting to #{label}...")

    case SmartBrick.connect(scanner, dev.uuid) do
      {:ok, device} ->
        wait_for_handshake(scanner, device)

      {:error, reason} ->
        IO.puts("Connection failed: #{inspect(reason)}")
        devices = SmartBrick.Scanner.discovered(scanner)
        scan_prompt(scanner, devices)
    end
  end

  defp wait_for_handshake(scanner, device) do
    IO.puts("Waiting for handshake...")

    receive do
      {:smart_brick_connected, info} ->
        device_phase(scanner, device, info)

      {:smart_brick_disconnect} ->
        IO.puts("Disconnected during handshake.")
        devices = SmartBrick.Scanner.discovered(scanner)
        scan_prompt(scanner, devices)
    after
      @connect_timeout_ms ->
        IO.puts("Handshake timed out.")
        Device.disconnect(device)
        devices = SmartBrick.Scanner.discovered(scanner)
        scan_prompt(scanner, devices)
    end
  end

  # -- Device phase --------------------------------------------------------

  defp device_phase(scanner, device, info) do
    print_dashboard(device, info)
    device_loop(scanner, device)
  end

  defp device_loop(scanner, device) do
    flush_events()

    case prompt("> ") do
      "v" -> cmd_set_volume(device)
      "n" -> cmd_set_name(device)
      "r" -> cmd_read_register(device)
      "i" -> cmd_refresh_info(device)
      "d" ->
        Device.disconnect(device)
        IO.puts("Disconnected.\n")
        devices = SmartBrick.Scanner.discovered(scanner)
        scan_prompt(scanner, devices)
        return_early()

      "q" ->
        Device.disconnect(device)
        SmartBrick.Scanner.stop(scanner)
        IO.puts("Bye.")
        return_early()

      "?" ->
        print_help()

      "" ->
        :ok

      other ->
        IO.puts("Unknown command: #{other}  (type ? for help)")
    end

    unless returned_early?() do
      device_loop(scanner, device)
    end
  end

  # We use the process dictionary to signal early return from the recursive loop.
  # This avoids needing throw/catch for control flow.
  defp return_early, do: Process.put(:cli_return, true)
  defp returned_early? do
    case Process.delete(:cli_return) do
      true -> true
      _ -> false
    end
  end

  defp print_dashboard(device, info) do
    battery = Device.battery(device)
    volume = Device.volume(device)

    IO.puts("""

    Connected to #{info.name || "unknown"}
      Model:    #{info.model}
      Firmware: #{info.firmware}
      MAC:      #{info.mac}
      Battery:  #{battery}%
      Volume:   #{volume}

    Commands:  v=volume  n=name  r=register  i=info  d=disconnect  q=quit  ?=help
    """)
  end

  defp print_help do
    IO.puts("""
      [v] Set volume (high / medium / low)
      [n] Set device name (max 12 chars)
      [r] Read a raw register by name
      [i] Refresh device info dashboard
      [d] Disconnect and return to scan
      [q] Quit
    """)
  end

  # -- Commands ------------------------------------------------------------

  defp cmd_set_volume(device) do
    case prompt("Volume (high/medium/low): ") do
      "high" -> do_set_volume(device, :high)
      "medium" -> do_set_volume(device, :medium)
      "low" -> do_set_volume(device, :low)
      "h" -> do_set_volume(device, :high)
      "m" -> do_set_volume(device, :medium)
      "l" -> do_set_volume(device, :low)
      _ -> IO.puts("  Cancelled. Use: high, medium, or low")
    end
  end

  defp do_set_volume(device, level) do
    case Device.set_volume(device, level) do
      :ok ->
        vol = Device.volume(device)
        IO.puts("  Volume set to #{vol}")

      {:error, reason} ->
        IO.puts("  Failed: #{inspect(reason)}")
    end
  end

  defp cmd_set_name(device) do
    name = prompt("New name (max 12 chars): ")

    if name == "" do
      IO.puts("  Cancelled.")
    else
      case Device.set_name(device, name) do
        :ok ->
          info = Device.info(device)
          IO.puts("  Name set to: #{info.name}")

        {:error, reason} ->
          IO.puts("  Failed: #{inspect(reason)}")
      end
    end
  end

  defp cmd_read_register(device) do
    IO.puts("  Registers: battery_level, device_model, firmware_revision,")
    IO.puts("    hub_local_name, user_volume, primary_mac_address, upgrade_state,")
    IO.puts("    charging_state, current_att_mtu, travel_mode")
    input = prompt("Register name: ")

    if input == "" do
      IO.puts("  Cancelled.")
    else
      try do
        register = String.to_existing_atom(input)

        case Device.read_register(device, register) do
          {:ok, data} ->
            hex = Base.encode16(data)
            ascii = for <<b <- data>>, b in 0x20..0x7E, into: "", do: <<b>>
            IO.puts("  #{input} = #{hex}")
            if ascii != "", do: IO.puts("  ASCII: #{ascii}")

          {:error, reason} ->
            IO.puts("  Failed: #{inspect(reason)}")
        end
      rescue
        ArgumentError ->
          IO.puts("  Unknown register: #{input}")
      end
    end
  end

  defp cmd_refresh_info(device) do
    info = Device.info(device)
    print_dashboard(device, info)
  end

  # -- Helpers -------------------------------------------------------------

  defp flush_events do
    receive do
      {:smart_brick_battery, level} ->
        IO.puts("  [battery: #{level}%]")
        flush_events()

      {:smart_brick_charging, state} ->
        label = if state == 0, do: "not charging", else: "charging (#{state})"
        IO.puts("  [#{label}]")
        flush_events()

      {:smart_brick_volume, level} ->
        IO.puts("  [volume: #{level}]")
        flush_events()

      {:smart_brick_disconnect} ->
        IO.puts("\n  Device disconnected!")
        Process.put(:cli_return, true)
    after
      0 -> :ok
    end
  end

  defp prompt(text) do
    IO.gets(text)
    |> case do
      :eof -> "q"
      {:error, _} -> "q"
      line -> String.trim(line)
    end
  end
end
