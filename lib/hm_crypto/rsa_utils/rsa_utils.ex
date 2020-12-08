defmodule HmCrypto.RsaUtils do
  alias HmCrypto.RsaUtils.{RsaPublicKey, RsaPrivateKey}
  require HmCrypto.RsaUtils.{RsaPublicKey, RsaPrivateKey}

  @doc """

  Extracts public key from private key and represents it as tuple.

  ## Usage

    ```
    HmCrypto.RsaUtils.public_key_from_private_key(private_key)
    {:RSAPublicKey, 16476722831871279117710250600091927580290930526218599633310724084700168598073759, 65537}
    ```

  """

  @spec public_key_from_private_key(RsaPrivateKey.t() | String.t()) :: RsaPublicKey.t()
  def public_key_from_private_key(
        RsaPrivateKey.record(modulus: modulus, publicExponent: public_exponent)
      ) do
    RsaPublicKey.record(modulus: modulus, publicExponent: public_exponent)
  end

  def public_key_from_private_key(private_key) when is_binary(private_key) do
    private_key
    |> HmCrypto.PublicKey.parse_pem()
    |> public_key_from_private_key()
  end

  @doc """

  Function encodes tuple representation of RSA key to PEM format (string).
  If string is given as argument - returns it as is.

  """

  @spec encode_pem(RsaPrivateKey.t() | RsaPublicKey.t() | String.t()) :: String.t()
  def encode_pem(RsaPublicKey.record() = rsa_key) do
    to_pem(RsaPublicKey.key_type(), rsa_key)
  end

  def encode_pem(RsaPrivateKey.record() = rsa_key) do
    to_pem(RsaPrivateKey.key_type(), rsa_key)
  end

  def encode_pem(rsa_key) when is_binary(rsa_key), do: rsa_key

  defp to_pem(key_type, rsa_key) do
    pem_entry = [:public_key.pem_entry_encode(key_type, rsa_key)]
    :public_key.pem_encode(pem_entry)
  end
end
