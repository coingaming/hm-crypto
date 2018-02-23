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

  test "should be able to validate signature with whitespaces" do
    signature =
      """
      sJqzygg4bBVOBs216w8yJLvlG3aazM59cFKujqxIJEbh4FiFbUKfEPtaUSNa
      YPJGHILAo1+Bdro1m6O1lVSsNdZU2zfUtZFKeRSiTE2em6KorbfqsZ0wsyGN
      FXMptaidpCTpCAl2jWsD5T6yaamU7Da9LS4lGUaFe55GONmdgH7T3QYUS5vD
      hM2l2Az6J9B62zKOX/PVMBAeEDuyW/4bUlQuuOxlG2jScpA2z/uQi5EiTyJ+
      4rRnUfiM5ifdzCAgLrhCJu/5mD9IkceQJyrKHZbjb+5Q/KQ6FTCj0+imiv0A
      a7YyDyA28uMSR2PhwfhNuASBgy/vX6k2s71I4sWVWA==
      """

    assert true == HmCrypto.valid?("message", signature)
  end
end
