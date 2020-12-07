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

  @spec public_key_from_private_key(RsaPrivateKey.t()) :: RsaPublicKey.t()
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
end
