defmodule HmCryptoTest do
  use ExUnit.Case

  test "sign and verify with default keypair" do
    signature = HmCrypto.sign!("message")

    assert {:ok, _} = Base.decode64(signature)

    assert true == HmCrypto.valid?("message", signature)
    assert false == HmCrypto.valid?("invalid message", signature)
  end

  test "sign and verify with custom keypair and digest_type" do
    public = File.read!("#{:code.priv_dir(:hm_crypto)}/custom_pub.pem")
    private = File.read!("#{:code.priv_dir(:hm_crypto)}/custom_priv.pem")
    digest_type = :md5

    signature = HmCrypto.sign!("message", digest_type, private)

    assert {:ok, _} = Base.decode64(signature)

    assert true == HmCrypto.valid?("message", signature, digest_type, public)
    assert false == HmCrypto.valid?("invalid message", signature, digest_type, public)
  end

  test "HmCrypto.valid? returns false when signature is not base64 string" do
    assert false == HmCrypto.valid?("message", "not base64 string")
  end
end
