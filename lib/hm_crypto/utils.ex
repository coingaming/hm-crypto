defmodule HmCrypto.Utils do
  import HmCrypto.PublicKey

  @doc """

  Extracts public key from private key and represents it as tuple.

  ## Usage

    ```
    HmCrypto.Utils.public_key_from_private_key(private_key)
    {:RSAPublicKey, 16476722831871279117710250600091927580290930526218599633310724084700168598073759, 65537}
    ```

  """

  @spec public_key_from_private_key(HmCrypto.PublicKey.rsa_key()) :: HmCrypto.PublicKey.t()
  def public_key_from_private_key(private_key) when is_tuple(private_key) do
    public_modulus = elem(private_key, 2)
    public_exponent = elem(private_key, 3)
    HmCrypto.PublicKey.record(modulus: public_modulus, publicExponent: public_exponent)
  end

  def public_key_from_private_key(private_key) when is_binary(private_key) do
    private_key
    |> parse_pem()
    |> public_key_from_private_key()
  end
end
