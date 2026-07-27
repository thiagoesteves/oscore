defmodule Oscore.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/thiagoesteves/oscore"

  def project do
    [
      app: :oscore,
      version: @version,
      elixir: "~> 1.16",
      name: "OSCORE",
      source_url: @source_url,
      homepage_url: @source_url,
      start_permanent: Mix.env() == :prod,
      test_coverage: test_coverage(),
      aliases: aliases(),
      deps: deps(),
      docs: docs(),
      package: package(),
      description: description(),
      dialyzer: [
        plt_file: {:no_warn, "priv/plts/dialyzer.plt"}
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp description do
    """
    RFC 8613 (OSCORE) message protection for CoAP, with the protocol core
    implemented in Rust via a Rustler NIF.
    """
  end

  defp package do
    [
      files: [
        "lib",
        "native",
        "checksum-*.exs",
        "mix.exs",
        "README.md",
        "LICENSE.md",
        "CHANGELOG.md",
        ".formatter.exs"
      ],
      maintainers: ["Thiago Esteves"],
      licenses: ["MIT"],
      links: %{
        Documentation: "https://hexdocs.pm/oscore",
        Changelog: "https://hexdocs.pm/oscore/changelog.html",
        GitHub: @source_url
      }
    ]
  end

  defp docs do
    [
      main: "OSCORE",
      source_ref: "v#{@version}",
      extras: ["README.md", "LICENSE.md", "CHANGELOG.md"],
      skip_undefined_reference_warnings_on: ["CHANGELOG.md"]
    ]
  end

  defp deps do
    [
      {:rustler, "~> 0.38"},
      {:ex_doc, "~> 0.34", only: [:dev, :test], runtime: false},
      {:mix_audit, "~> 2.1", only: [:dev, :test], runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false}
    ]
  end

  def test_coverage do
    [
      summary: [threshold: 80],
      ignore_modules: [
        Oscore.Native
      ]
    ]
  end

  defp aliases do
    [
      release: [
        "cmd git tag v#{@version} -f",
        "cmd git push",
        "cmd git push --tags",
        "hex.publish --yes"
      ],
      "test.ci": [
        "format --check-formatted",
        "deps.unlock --check-unused",
        "credo --strict",
        "dialyzer"
      ]
    ]
  end
end
