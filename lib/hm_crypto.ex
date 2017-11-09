defmodule HmCrypto do
  import HmCrypto.PublicKey

  @rsa_digest_types ~w(md5 ripemd160 sha sha224 sha256 sha384 sha512)a

  @default_digest_type (
    digest_type = Application.get_env(:hm_crypto, :digest_type)
    true = Enum.member?(@rsa_digest_types, digest_type)
    digest_type
  )

  @default_private_key Application.get_env(:hm_crypto, :private_key).() |> parse_pem
  @default_public_key Application.get_env(:hm_crypto, :public_key).() |> parse_pem

  def sign!(message, digest_type \\ @default_digest_type, private_key \\ @default_private_key)
      when is_binary(message) do
    :public_key.sign(message, digest_type, parse_pem(private_key))
    |> Base.encode64
  end

  def valid?(message, encoded_signature, digest_type \\ @default_digest_type,
             public_key \\ @default_public_key)
      when is_binary(message) do
    case Base.decode64(encoded_signature) do
      {:ok, signature} ->
        :public_key.verify(message, digest_type, signature, parse_pem(public_key))
      _ -> false
    end
  end
end
