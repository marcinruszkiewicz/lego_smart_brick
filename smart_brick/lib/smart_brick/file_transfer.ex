defmodule SmartBrick.FileTransfer do
  @moduledoc """
  WDX file transfer protocol (FTC/FTD) for LEGO Smart Brick.

  Data Channel 1 (FTC) = File Transfer Control (commands and acks).
  Data Channel 2 (FTD) = File Transfer Data (bulk payload).

  Protocol from: https://github.com/nathankellenicki/node-smartplay/blob/main/notes/FILE_TRANSFER.md
  """

  import Bitwise

  # -- FTC command bytes (wire) --------------------------------------------
  @ftc_request 0x01
  @ftc_ack 0x02
  @ftc_confirm 0x05
  @ftc_confirm_ack 0x06
  @ftc_end 0x0A

  # -- File handles --------------------------------------------------------
  @handle_file_list 0x00
  @handle_firmware 0x01
  @handle_fault_log 0x02
  @handle_telemetry 0x03

  # -- Permission bits -----------------------------------------------------
  @perm_read 0x01
  @perm_write 0x02
  @perm_erase 0x04
  @perm_verify 0x08

  # -- Public structs ------------------------------------------------------

  defmodule FileEntry do
    @moduledoc "Single file entry from the file list (40-byte record)."
    defstruct [:handle, :permissions, :size, :name, :version]

    @type t :: %__MODULE__{
            handle: non_neg_integer(),
            permissions: non_neg_integer(),
            size: non_neg_integer(),
            name: String.t(),
            version: String.t()
          }
  end

  defmodule TelmHeader do
    @moduledoc "TELM telemetry header (bytes 0-16), payload at 17+ is encrypted."
    defstruct [:fragment_index, :version, :mac, :payload]

    @type t :: %__MODULE__{
            fragment_index: non_neg_integer(),
            version: non_neg_integer(),
            mac: binary(),
            payload: binary()
          }
  end

  # -- Packet builders (send to FTC) ---------------------------------------

  @doc """
  Build request-file packet for FTC. Use handle 0 for file list, 1-3 for firmware/fault/telemetry.
  """
  @spec build_request(non_neg_integer()) :: binary()
  def build_request(handle) when handle in 0..3 do
    <<@ftc_request, handle, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x01>>
  end

  @doc "Build confirm-receipt packet after end-of-transfer."
  @spec build_confirm(non_neg_integer()) :: binary()
  def build_confirm(handle) when handle in 0..3 do
    <<@ftc_confirm, handle, 0x00>>
  end

  # -- FTC parser (incoming from Data Channel 1) --------------------------

  @doc """
  Parse FTC notification. Returns:
  - `{:ack, handle}` for 02 HH 00 00 00 30 00
  - `{:end, handle}` for 0A HH 00
  - `{:confirm_ack, handle}` for 06 HH 00 00
  - `:unknown` for other payloads
  """
  @spec parse_ftc(binary()) :: {:ack, non_neg_integer()} | {:end, non_neg_integer()} | {:confirm_ack, non_neg_integer()} | :unknown
  def parse_ftc(<<@ftc_ack, handle, 0x00, 0x00, 0x00, 0x30, 0x00>>), do: {:ack, handle}
  def parse_ftc(<<@ftc_end, handle, 0x00>>), do: {:end, handle}
  def parse_ftc(<<@ftc_confirm_ack, handle, 0x00, 0x00>>), do: {:confirm_ack, handle}
  def parse_ftc(_), do: :unknown

  @doc "Returns true if the binary looks like an FTC packet (short, known first byte)."
  @spec is_ftc?(binary()) :: boolean()
  def is_ftc?(<<@ftc_ack, _::binary>>), do: true
  def is_ftc?(<<@ftc_end, _::binary>>), do: true
  def is_ftc?(<<@ftc_confirm_ack, _::binary>>), do: true
  def is_ftc?(_), do: false

  # -- FTD parser (incoming from Data Channel 2) ---------------------------

  @doc """
  Parse FTD notification. First byte is fragment index.
  - For file list: bytes 1-2 = first_handle, byte 3 = count, then 40*count file entries.
  - For file content: bytes 1+ = raw file data (may be one fragment or more).
  Returns `{:file_list, [FileEntry.t()]}` or `{:fragment, index, data}`.
  """
  @spec parse_ftd(binary(), :file_list | :file_content) :: {:file_list, [FileEntry.t()]} | {:fragment, non_neg_integer(), binary()}
  def parse_ftd(<<index, rest::binary>>, :file_list) do
    case rest do
      <<_first_handle, count, entries_bin::binary>> when count in 1..16 ->
        entries = parse_file_entries(entries_bin, count)
        {:file_list, entries}

      _ ->
        {:fragment, index, rest}
    end
  end

  def parse_ftd(<<index, data::binary>>, :file_content) do
    {:fragment, index, data}
  end

  # -- File entry parser (40 bytes each) -----------------------------------

  @doc "Parse a single 40-byte file entry. Format: handle(2) + permissions(2) + size(4) + name(16) + version(16), all LE where applicable."
  @spec parse_file_entry(binary()) :: {:ok, FileEntry.t()} | :error
  def parse_file_entry(<<handle::little-16, perms::little-16, size::little-32, name_bin::binary-16, version_bin::binary-16>>) do
    name = trim_null_padded(name_bin)
    version = trim_null_padded(version_bin)
    {:ok, %FileEntry{handle: handle, permissions: perms, size: size, name: name, version: version}}
  end

  def parse_file_entry(_), do: :error

  defp parse_file_entries(bin, count) do
    entry_size = 40
    total = count * entry_size

    case bin do
      <<entries_bin::binary-size(total), _::binary>> ->
        for <<entry::binary-40 <- entries_bin>> do
          {:ok, e} = parse_file_entry(entry)
          e
        end

      _ ->
        []
    end
  end

  defp trim_null_padded(bin) do
    case :binary.split(bin, <<0>>) do
      [str, _] -> str
      [str] -> str
    end
    |> String.trim(<<0>>)
  end

  # -- TELM header parser (telemetry file content) --------------------------

  @doc """
  Parse TELM header from telemetry file content. Bytes 0-16 are header;
  bytes 17+ are encrypted payload. MAC in header is 6 bytes, reversed byte order.
  """
  @spec parse_telm(binary()) :: {:ok, TelmHeader.t()} | :error
  def parse_telm(<<frag_index, "TELM", version, _reserved::binary-2, _pad, mac_reversed::binary-6, _sep::binary-2, payload::binary>>) do
    mac = reverse_6bytes(mac_reversed)
    {:ok, %TelmHeader{fragment_index: frag_index, version: version, mac: mac, payload: payload}}
  end

  def parse_telm(_), do: :error

  defp reverse_6bytes(<<a, b, c, d, e, f>>), do: <<f, e, d, c, b, a>>

  # -- Permission helpers --------------------------------------------------

  @doc "Format permissions as read/write/erase/verify flags."
  @spec format_permissions(non_neg_integer()) :: String.t()
  def format_permissions(perms) do
    [
      (band(perms, @perm_read) != 0 && "R"),
      (band(perms, @perm_write) != 0 && "W"),
      (band(perms, @perm_erase) != 0 && "E"),
      (band(perms, @perm_verify) != 0 && "V")
    ]
    |> Enum.filter(& &1)
    |> Enum.join("")
  end

  # -- Constants for Device routing ----------------------------------------

  def handle_file_list, do: @handle_file_list
  def handle_firmware, do: @handle_firmware
  def handle_fault_log, do: @handle_fault_log
  def handle_telemetry, do: @handle_telemetry
end
