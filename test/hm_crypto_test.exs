defmodule HmCryptoTest do
  use ExUnit.Case
  doctest HmCrypto

  setup do
    %{
      payload: "message",
      digest_type: :sha256,
      public_key: File.read!("#{:code.priv_dir(:hm_crypto)}/demo_pub.pem"),
      private_key: File.read!("#{:code.priv_dir(:hm_crypto)}/demo_priv.pem")
    }
  end

  test "sign and verify", %{
    digest_type: digest_type,
    public_key: public_key,
    private_key: private_key,
    payload: payload
  } do
    signature = HmCrypto.sign!(payload, digest_type, private_key)

    assert {:ok, _} = Base.decode64(signature)
    assert true == HmCrypto.valid?(payload, signature, digest_type, public_key)
    assert false == HmCrypto.valid?("hello #{payload}", signature, digest_type, public_key)
  end

  test "HmCrypto.valid? returns false when signature is not base64 string", %{
    digest_type: digest_type,
    public_key: public_key,
    payload: payload
  } do
    assert false == HmCrypto.valid?(payload, "not base64 string", digest_type, public_key)
  end

  test "should be able to validate signature with whitespaces", %{
    digest_type: digest_type,
    public_key: public_key,
    private_key: private_key,
    payload: payload
  } do
    raw_signature = HmCrypto.sign!(payload, digest_type, private_key)

    signature =
      raw_signature
      |> String.split_at(round(String.length(raw_signature) / 2))
      |> Tuple.to_list()
      |> Enum.join(" \n")

    assert true == HmCrypto.valid?(payload, signature, digest_type, public_key)
  end
end
