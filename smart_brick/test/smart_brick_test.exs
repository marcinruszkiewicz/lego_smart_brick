defmodule SmartBrickTest do
  use ExUnit.Case

  alias SmartBrick.Constants
  alias SmartBrick.Protocol
  alias SmartBrick.FileTransfer

  describe "Constants" do
    test "register_byte/name round-trip" do
      assert Constants.register_byte(:battery_level) == 0x20
      assert Constants.register_name(0x20) == :battery_level
    end

    test "unknown register byte returns nil" do
      assert Constants.register_name(0xFF) == nil
    end

    test "volume_level mapping" do
      assert Constants.volume_level(:high) == 100
      assert Constants.volume_level(:medium) == 40
      assert Constants.volume_level(:low) == 10
    end

    test "subscription_uuids returns 5 UUIDs" do
      assert length(Constants.subscription_uuids()) == 5
    end
  end

  describe "Protocol.encode_read/1" do
    test "encodes a register read command" do
      assert Protocol.encode_read(:device_model) == <<0x01, 0x21>>
      assert Protocol.encode_read(:battery_level) == <<0x01, 0x20>>
    end
  end

  describe "Protocol.encode_write/2" do
    test "encodes a register write with binary data" do
      assert Protocol.encode_write(:user_volume, <<100>>) == <<0x02, 0x81, 100>>
    end

    test "encodes a register write with list data" do
      assert Protocol.encode_write(:ux_signal, [0xEA, 0x00]) == <<0x02, 0x90, 0xEA, 0x00>>
    end
  end

  describe "Protocol.decode_response/1" do
    test "decodes a valid response" do
      raw = <<0x03, 0x20, 75>>
      assert {:ok, %{register: :battery_level, data: <<75>>}} = Protocol.decode_response(raw)
    end

    test "decodes unknown register as integer" do
      raw = <<0x03, 0xFF, 1, 2, 3>>
      assert {:ok, %{register: 0xFF, data: <<1, 2, 3>>}} = Protocol.decode_response(raw)
    end

    test "rejects non-response frames" do
      assert :error = Protocol.decode_response(<<0x01, 0x20>>)
      assert :error = Protocol.decode_response(<<>>)
      assert :error = Protocol.decode_response(<<0x03>>)
    end
  end

  describe "Protocol.register_key/1" do
    test "produces consistent keys" do
      assert Protocol.register_key(:battery_level) == "reg:20"
      assert Protocol.register_key(0x20) == "reg:20"
    end
  end

  describe "Protocol parse helpers" do
    test "parse_string handles null terminator" do
      assert Protocol.parse_string("Hello\0World") == "Hello"
      assert Protocol.parse_string("NoNull") == "NoNull"
    end

    test "parse_mac_address formats 6 bytes" do
      mac = Protocol.parse_mac_address(<<0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF>>)
      assert mac == "AA:BB:CC:DD:EE:FF"
    end

    test "parse_battery_level extracts first byte" do
      assert Protocol.parse_battery_level(<<85>>) == 85
      assert Protocol.parse_battery_level(<<>>) == 0
    end

    test "parse_volume extracts first byte" do
      assert Protocol.parse_volume(<<40>>) == 40
    end
  end

  describe "FileTransfer" do
    test "build_request produces 12-byte packet" do
      assert byte_size(FileTransfer.build_request(0)) == 12
      assert <<0x01, 0x03, _::binary>> = FileTransfer.build_request(3)
    end

    test "build_confirm produces 3-byte packet" do
      assert FileTransfer.build_confirm(2) == <<0x05, 0x02, 0x00>>
    end

    test "parse_ftc recognizes ack, end, confirm_ack" do
      assert FileTransfer.parse_ftc(<<0x02, 0x03, 0x00, 0x00, 0x00, 0x30, 0x00>>) == {:ack, 0x03}
      assert FileTransfer.parse_ftc(<<0x0A, 0x03, 0x00>>) == {:end, 0x03}
      assert FileTransfer.parse_ftc(<<0x06, 0x03, 0x00, 0x00>>) == {:confirm_ack, 0x03}
      assert FileTransfer.parse_ftc(<<0x99>>) == :unknown
    end

    test "parse_file_entry parses 40-byte entry" do
      # handle=1, perms=0x200, size=100, name 16 bytes, version 16 bytes
      name_16 = String.pad_trailing("Firmware", 16, "\0")
      version_16 = String.pad_trailing("1.0", 16, "\0")
      bin = <<1::little-16, 0x200::little-16, 100::little-32, name_16::binary, version_16::binary>>
      assert {:ok, entry} = FileTransfer.parse_file_entry(bin)
      assert entry.handle == 1
      assert entry.permissions == 0x200
      assert entry.size == 100
      assert entry.name =~ "Firmware"
      assert entry.version =~ "1.0"
    end

    test "format_permissions" do
      assert FileTransfer.format_permissions(0x01) == "R"
      assert FileTransfer.format_permissions(0x05) == "RE"
    end
  end
end
