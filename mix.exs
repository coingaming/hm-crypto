defmodule HmCrypto.Mixfile do
  use Mix.Project

  def project do
    [
      app: :hm_crypto,
      version: "VERSION" |> File.read!() |> String.trim(),
      elixir: "~> 1.6",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),

      # excoveralls
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [
        coveralls: :test,
        "coveralls.travis": :test,
        "coveralls.circle": :test,
        "coveralls.semaphore": :test,
        "coveralls.post": :test,
        "coveralls.detail": :test,
        "coveralls.html": :test
      ],
      # dialyxir
      dialyzer: [
        ignore_warnings: ".dialyzer_ignore",
        plt_add_apps: [:public_key],
        plt_file: {:no_warn, "plts/dialyzer.plt"}
      ],
      # ex_doc
      name: "HmCrypto",
      source_url: "https://github.com/heathmont/hm-crypto",
      homepage_url: "https://github.com/heathmont/hm-crypto",
      docs: [main: "readme", extras: ["README.md"]],
      # hex.pm stuff
      description: "Elixir library for signing and validating requests",
      package: [
        licenses: ["Apache 2.0"],
        organization: "coingaming",
        files: ["lib", "priv", "mix.exs", "README*", "VERSION*"],
        maintainers: ["tim2CF", "nazipov", "ysemeniuk"],
        links: %{
          "GitHub" => "https://github.com/heathmont/hm-crypto"
        }
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"},
      {:benchfella, "~> 0.3.0", only: [:dev, :test], runtime: false},
      {:excoveralls, "~> 0.13", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.0", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.23", only: [:dev, :test], runtime: false},
      {:credo, "~> 0.8", only: [:dev, :test], runtime: false},
      {:boilex, "~> 0.2.1", only: [:dev, :test], runtime: false}
    ]
  end

  # Specifies which paths to compile per environment.
  defp elixirc_paths(:test), do: ["lib", "test/support", "bench/support"]
  defp elixirc_paths(:dev), do: ["lib", "bench/support"]
  defp elixirc_paths(_), do: ["lib"]
end
