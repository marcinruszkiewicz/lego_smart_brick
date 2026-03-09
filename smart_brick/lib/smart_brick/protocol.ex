defmodule SmartBrick.Protocol do
  @moduledoc """
  Binary encode/decode for the LEGO Smart Brick register protocol.

  The brick communicates over a single BLE characteristic (Control Point)
  using a simple framing:

    Read:     <<0x01, register>>
    Write:    <<0x02, register, data…>>
    Response: <<0x03, register, data…>>
  """

  alias SmartBrick.Constants

  # -- Encode --------------------------------------------------------------

  @doc "Encode a register read command."
  @spec encode_read(atom()) :: binary()
  def encode_read(register) when is_atom(register) do
    <<Constants.command_read(), Constants.register_byte(register)>>
  end

  @doc "Encode a register write command with a payload."
  @spec encode_write(atom(), binary() | [non_neg_integer()]) :: binary()
  def encode_write(register, data) when is_atom(register) and is_binary(data) do
    <<Constants.command_write(), Constants.register_byte(register), data::binary>>
  end

  def encode_write(register, data) when is_atom(register) and is_list(data) do
    encode_write(register, :erlang.list_to_binary(data))
  end

  # -- Decode --------------------------------------------------------------

  @doc """
  Decode a raw notification from the Control Point characteristic.

  Returns `{:ok, %{register: atom | non_neg_integer, data: binary}}` for
  valid response frames, or `:error` for anything else.
  """
  @spec decode_response(binary()) :: {:ok, map()} | :error
  def decode_response(<<0x03, register_byte, data::binary>>) do
    register = Constants.register_name(register_byte) || register_byte
    {:ok, %{register: register, data: data}}
  end

  def decode_response(_), do: :error

  @doc """
  Build a string key for matching pending requests to responses.
  """
  @spec register_key(atom() | non_neg_integer()) :: String.t()
  def register_key(register) when is_atom(register) do
    byte = Constants.register_byte(register)
    "reg:" <> String.pad_leading(Integer.to_string(byte, 16), 2, "0")
  end

  def register_key(byte) when is_integer(byte) do
    "reg:" <> String.pad_leading(Integer.to_string(byte, 16), 2, "0")
  end

  # -- Parse helpers -------------------------------------------------------

  @doc "Parse a null-terminated (or full-length) UTF-8 string from register data."
  @spec parse_string(binary()) :: String.t()
  def parse_string(data) do
    case :binary.split(data, <<0>>) do
      [str, _rest] -> str
      [str] -> str
    end
  end

  @doc "Parse a device model name."
  def parse_device_model(data), do: parse_string(data)

  @doc "Parse a firmware revision string."
  def parse_firmware_revision(data), do: parse_string(data)

  @doc "Parse the hub local name."
  def parse_hub_local_name(data), do: parse_string(data)

  @doc "Parse a 6-byte MAC address into colon-separated hex."
  @spec parse_mac_address(binary()) :: String.t()
  def parse_mac_address(<<a, b, c, d, e, f, _rest::binary>>) do
    [a, b, c, d, e, f]
    |> Enum.map_join(":", &String.pad_leading(Integer.to_string(&1, 16), 2, "0"))
    |> String.upcase()
  end

  def parse_mac_address(_), do: ""

  @doc "Parse a single-byte battery level (0–100)."
  @spec parse_battery_level(binary()) :: non_neg_integer()
  def parse_battery_level(<<level, _rest::binary>>), do: level
  def parse_battery_level(_), do: 0

  @doc "Parse a single-byte volume level."
  @spec parse_volume(binary()) :: non_neg_integer()
  def parse_volume(<<level, _rest::binary>>), do: level
  def parse_volume(_), do: 0

  @doc "Parse a single-byte charging state."
  @spec parse_charging_state(binary()) :: non_neg_integer()
  def parse_charging_state(<<state, _rest::binary>>), do: state
  def parse_charging_state(_), do: 0

  @doc "Parse a single-byte upgrade state."
  @spec parse_upgrade_state(binary()) :: non_neg_integer()
  def parse_upgrade_state(<<state, _rest::binary>>), do: state
  def parse_upgrade_state(_), do: 0
end
