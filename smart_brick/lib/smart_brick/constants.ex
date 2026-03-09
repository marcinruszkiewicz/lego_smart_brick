defmodule SmartBrick.Constants do
  @moduledoc """
  BLE service/characteristic UUIDs, register definitions, command types,
  and configuration values for the LEGO Smart Play brick protocol.

  Ported from https://github.com/nathankellenicki/node-smartplay
  """

  # -- BLE Service UUIDs ---------------------------------------------------

  @fef6_service_uuid "0000fef6-0000-1000-8000-00805f9b34fb"
  @fef6_service_short "fef6"

  # -- FEF6 Characteristic UUIDs (base: 005f000X-2ff2-4ed5-b045-4c7463617865)

  @control_point_uuid "005f0002-2ff2-4ed5-b045-4c7463617865"
  @data_channel_1_uuid "005f0003-2ff2-4ed5-b045-4c7463617865"
  @data_channel_2_uuid "005f0004-2ff2-4ed5-b045-4c7463617865"
  @data_channel_3_uuid "005f0005-2ff2-4ed5-b045-4c7463617865"

  # -- Custom LEGO Service (base: 005f000X-3ff2-4ed5-b045-4c7463617865)

  @custom_service_uuid "005f0001-3ff2-4ed5-b045-4c7463617865"
  @bidirectional_uuid "005f000a-3ff2-4ed5-b045-4c7463617865"

  # -- Standard GATT

  @service_changed_uuid "00002a05-0000-1000-8000-00805f9b34fb"

  # -- LEGO Bluetooth SIG company identifier

  @lego_company_id 0x0397

  # -- Protocol constants

  @keepalive_data <<0xEA, 0x00>>
  @poll_interval_ms 500
  @default_timeout_ms 10_000

  # -- Public accessors ----------------------------------------------------

  def fef6_service_uuid, do: @fef6_service_uuid
  def fef6_service_short, do: @fef6_service_short

  def control_point_uuid, do: @control_point_uuid
  def data_channel_1_uuid, do: @data_channel_1_uuid
  def data_channel_2_uuid, do: @data_channel_2_uuid
  def data_channel_3_uuid, do: @data_channel_3_uuid

  def custom_service_uuid, do: @custom_service_uuid
  def bidirectional_uuid, do: @bidirectional_uuid
  def service_changed_uuid, do: @service_changed_uuid

  def lego_company_id, do: @lego_company_id

  def keepalive_data, do: @keepalive_data
  def poll_interval_ms, do: @poll_interval_ms
  def default_timeout_ms, do: @default_timeout_ms

  @doc """
  All characteristic UUIDs to subscribe to after connection, in the order
  observed in the Android HCI capture (bidirectional first, then control
  point, then data channels, then service changed).
  """
  def subscription_uuids do
    [
      @bidirectional_uuid,
      @control_point_uuid,
      @data_channel_1_uuid,
      @data_channel_2_uuid,
      @data_channel_3_uuid
    ]
  end

  # -- Register definitions ------------------------------------------------

  @registers %{
    # BLE connection properties (0x01–0x0A)
    connection_parameter_update_req: 0x01,
    current_connection_parameters: 0x02,
    disconnect_req: 0x03,
    connection_security_level: 0x04,
    security_req: 0x05,
    service_changed: 0x06,
    delete_bonds: 0x07,
    current_att_mtu: 0x08,
    phy_update_req: 0x09,
    current_phy: 0x0A,
    # Device info (0x20–0x26)
    battery_level: 0x20,
    device_model: 0x21,
    firmware_revision: 0x22,
    enter_diagnostic_mode: 0x23,
    diagnostic_mode_complete: 0x24,
    disconnect_and_reset: 0x25,
    disconnect_configure_fota_and_reset: 0x26,
    # Hub properties (0x80–0x96)
    hub_local_name: 0x80,
    user_volume: 0x81,
    current_write_offset: 0x82,
    primary_mac_address: 0x84,
    upgrade_state: 0x85,
    signed_command_nonce: 0x86,
    signed_command: 0x87,
    update_state: 0x88,
    pipeline_stage: 0x89,
    ux_signal: 0x90,
    ownership_proof: 0x91,
    charging_state: 0x93,
    factory_reset: 0x95,
    travel_mode: 0x96
  }

  @register_by_byte Map.new(@registers, fn {name, byte} -> {byte, name} end)

  @doc "Convert a register atom to its byte value."
  @spec register_byte(atom()) :: non_neg_integer()
  def register_byte(name) when is_atom(name) do
    Map.fetch!(@registers, name)
  end

  @doc "Convert a register byte back to its atom name, or nil if unknown."
  @spec register_name(non_neg_integer()) :: atom() | nil
  def register_name(byte) when is_integer(byte) do
    Map.get(@register_by_byte, byte)
  end

  # -- Command types -------------------------------------------------------

  @command_read 0x01
  @command_write 0x02
  @command_response 0x03

  def command_read, do: @command_read
  def command_write, do: @command_write
  def command_response, do: @command_response

  # -- Volume levels -------------------------------------------------------

  @volume_high 100
  @volume_medium 40
  @volume_low 10

  def volume_high, do: @volume_high
  def volume_medium, do: @volume_medium
  def volume_low, do: @volume_low

  @doc "Convert a volume atom (:high, :medium, :low) to its byte value."
  @spec volume_level(atom()) :: non_neg_integer()
  def volume_level(:high), do: @volume_high
  def volume_level(:medium), do: @volume_medium
  def volume_level(:low), do: @volume_low

  # -- Upgrade state values ------------------------------------------------

  @upgrade_ready 0
  @upgrade_in_progress 1
  @upgrade_low_battery 2

  def upgrade_ready, do: @upgrade_ready
  def upgrade_in_progress, do: @upgrade_in_progress
  def upgrade_low_battery, do: @upgrade_low_battery
end
