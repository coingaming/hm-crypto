defmodule HmCrypto.UtilsTest do
  use ExUnit.Case
  doctest HmCrypto.Utils

  setup do
    %{
      public_key: File.read!("#{:code.priv_dir(:hm_crypto)}/demo_pub.pem"),
      private_key: File.read!("#{:code.priv_dir(:hm_crypto)}/demo_priv.pem")
    }
  end

  test "public_key_from_private_key", %{public_key: public_key, private_key: private_key} do
    parsed_public_key = HmCrypto.PublicKey.parse_pem(public_key)
    parsed_private_key = HmCrypto.PublicKey.parse_pem(private_key)

    assert HmCrypto.Utils.public_key_from_private_key(parsed_private_key) == parsed_public_key
    assert HmCrypto.Utils.public_key_from_private_key(private_key) == parsed_public_key
  end
end
