defmodule NfcCapture do
  @moduledoc """
  Entry point for NFC serial capture. Delegates to MacCapture.

  Run with:
    mix run -e "NfcCapture.run()"
    mix run -e "NfcCapture.run(port: \"/dev/cu.usbmodem14101\")"
  """

  defdelegate run(opts \\ []), to: MacCapture
end
