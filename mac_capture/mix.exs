defmodule MacCapture.MixProject do
  use Mix.Project

  @version "0.1.0"

  def project do
    [
      app: :mac_capture,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "Capture NFC ISO15693 JSON lines from Arduino serial and save/analyze.",
      package: []
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:circuits_uart, "~> 1.5"}
    ]
  end
end
