defmodule HmCrypto do
  import HmCrypto.PublicKey

  @type digest_type :: :sha | :sha224 | :sha256 | :sha384 | :sha512

  @digest_type_list ~w(sha sha224 sha256 sha384 sha512)a

  @moduledoc """

  Main functional API of `HmCrypto` application.
  Provides signing and validation functionality.

  """

  @doc """

  Returns list of availiable digest types.

  ## Examples

    ```
    iex> HmCrypto.digest_types
    [:sha, :sha224, :sha256, :sha384, :sha512]
    ```

  """

  @spec digest_types() :: [digest_type()]
  def digest_types, do: @digest_type_list

  @doc """

  Generates base64-encoded signature of payload according given
  digest_type and private_key.

  ## Usage

    ```
    signature = HmCrypto.sign!(payload, :sha512, priv_key)
    "XE54doOCtx+z2h9gILOHPKP8+RTnvQVAPUoKpux2PLZUBX2JVIaS3vNewQM6IpxvMzfewWm1H6j+SPbhhGpvcp3MiGo8426KlGoqg6jjuILAQ4jXzYrTa6HFBXhuk+Y34e0Hv1FKwbmVYXvn5RTmgYfI6vzA4spOoG/AMIis6hpnNE5lTsjHU76QtcVWJPfJKk2wDiZI9u2EWLGEq1BJuCfbZYSueNVe2aDqbZ7UANybyZsSHa1oPY6nP+FS5wm3zrKEdMV2PBGi63STg4WabBaaaB6s73GAA0IVogcysVtGKJ8vN17ion5zT6+r62DEHNGNGscjV7HTJd1tNNG9Iw=="
    ```

  """

  @spec sign!(binary(), digest_type(), HmCrypto.PrivateKey.key()) :: binary()
  def sign!(payload, digest_type, private_key)
      when is_binary(payload) and
             digest_type in @digest_type_list do
    payload
    |> :public_key.sign(digest_type, parse_pem(private_key))
    |> Base.encode64()
  end

  @doc """

  Validates base64-encoded signature according given
  payload, digest_type and public_key.
  Returns `true` if signature is valid, else returns `false`.

  ## Usage

    ```
    HmCrypto.valid?(payload, signature, :sha512, public_key)
    true
    ```

  """

  @spec valid?(binary(), binary(), digest_type(), HmCrypto.PublicKey.key()) :: boolean()
  def valid?(payload, encoded_signature, digest_type, public_key)
      when is_binary(payload) and
             is_binary(encoded_signature) and
             digest_type in @digest_type_list do
    encoded_signature
    |> Base.decode64(ignore: :whitespace)
    |> case do
      {:ok, signature} ->
        :public_key.verify(payload, digest_type, signature, parse_pem(public_key))

      _ ->
        false
    end
  end
end
