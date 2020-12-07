defmodule HmCrypto.PublicKey do
  alias HmCrypto.RsaUtils.{RsaPublicKey, RsaPrivateKey}
  require HmCrypto.RsaUtils.{RsaPublicKey, RsaPrivateKey}

  @type rsa_key :: RsaPublicKey.t() | RsaPrivateKey.t() | binary()

  @moduledoc """

  API to work with RSA keys.

  """

  @doc """

  Function parses binary (string) representation of RSA key to Erlang format (tuple).
  If tuple is given as argument - returns it as is.

  """

  @spec parse_pem(rsa_key()) :: RsaPublicKey.t() | RsaPrivateKey.t()
  def parse_pem(pem_string) when is_binary(pem_string) and pem_string != "" do
    [pem_entry] = :public_key.pem_decode(pem_string)
    :public_key.pem_entry_decode(pem_entry)
  end

  def parse_pem(RsaPublicKey.record() = pem), do: pem
  def parse_pem(RsaPrivateKey.record() = pem), do: pem

  @doc """

  Function encodes tuple representation of RSA key to PEM format (string).
  If string is given as argument - returns it as is.

  """

  @spec encode_pem(rsa_key()) :: String.t()
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
