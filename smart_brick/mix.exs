defmodule SmartBrick.MixProject do
  use Mix.Project

  @version "0.1.0"

  def project do
    [
      app: :smart_brick,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "Elixir BLE client for LEGO Smart Play bricks."
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:rustler_btleplug, "~> 0.0.17-alpha"},
      {:rustler, ">= 0.31.0", optional: true}
    ]
  end
end
