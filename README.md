# HmCrypto

[![CircleCI](https://circleci.com/gh/heathmont/hm-crypto.svg?style=shield&circle-token=c1b594b3ee6dadc82c44d0c0e6d68db18230e324)](https://circleci.com/gh/heathmont/hm-crypto)

Elixir library for signing and validating requests

## Installation

```elixir
def deps do
  [
    {:hm_crypto, git: "git@github.com:heathmont/hm-crypto.git", tag: "v0.1.1"}
  ]
end
```

## Configure

Add default keypair and digest type to `config.exs`:

```elixir
config :hm_crypto,
  digest_type: :sha256,
  private_key: fn -> File.read!("my_default_priv.pem") end,
  public_key: fn -> File.read!("my_default_pub.pem") end
```

Availiable digest types (see rsa_digest_type() in [docs](http://erlang.org/doc/man/public_key.html)) is md5, ripemd160, sha, sha224, sha256, sha384, sha512.

## Usage

`HmCrypto.sign!` returns base64 string. `HmCrypto.valid?` returns false if signature is not base64 string.

Sign and validate with default keypair:

```elixir
iex(2)> message = "my request"
"my request"
iex(3)> signature = HmCrypto.sign!(message)
"UEKR5uTlUZthtNLmJ1iO0qd8iKqmbwEHJwgyoAWXEjzyQDVLuOg906EyxCbvAksiuq2dITpDGalM29vI83032jXoPRep/qM+/tPIP+3Ic3DzgfVYoVfWTymRaMJ+wwOfV3w5DDB7muFaDjN68RngdUtSXlcKnn7wPiWNpBzVYNr0vF242Nfyh2tF8jCbgzASzF2D69Mkz00Bpc/SBB4IxejMn2Q/61OKAZ004iVjKPpFOea0668srvMkZ3+HgZC420CqOpIhHmOFaqLyTbN+hps7gxP9na1qcSsihBUkU8TvGYWzTY3PWStnKQxhgDEH6hsyrqhRWvGUAcmtMdBqUA=="
iex(4)> HmCrypto.valid?(message, signature)
true
```

Sign and validate with custom keypair and digest type:

```elixir
iex(5)> custom_pub_key = File.read!("custom_pub.pem")
"-----BEGIN PUBLIC KEY-----.......................-----END PUBLIC KEY-----\n"
iex(6)> custom_priv_key = File.read!("custom_priv.pem")
"-----BEGIN RSA PRIVATE KEY-----.......................-----END RSA PRIVATE KEY-----\n"
iex(7)> message = "my request with custom keypair"
"my request with custom keypair"
iex(8)> signature = HmCrypto.sign!(message, :sha512, custom_priv_key)
"XE54doOCtx+z2h9gILOHPKP8+RTnvQVAPUoKpux2PLZUBX2JVIaS3vNewQM6IpxvMzfewWm1H6j+SPbhhGpvcp3MiGo8426KlGoqg6jjuILAQ4jXzYrTa6HFBXhuk+Y34e0Hv1FKwbmVYXvn5RTmgYfI6vzA4spOoG/AMIis6hpnNE5lTsjHU76QtcVWJPfJKk2wDiZI9u2EWLGEq1BJuCfbZYSueNVe2aDqbZ7UANybyZsSHa1oPY6nP+FS5wm3zrKEdMV2PBGi63STg4WabBaaaB6s73GAA0IVogcysVtGKJ8vN17ion5zT6+r62DEHNGNGscjV7HTJd1tNNG9Iw=="
iex(9)> HmCrypto.valid?(message, signature, :sha512, custom_pub_key)
true
```
