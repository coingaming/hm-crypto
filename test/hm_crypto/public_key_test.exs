defmodule HmCrypto.PublicKeyTest do
  use ExUnit.Case
  doctest HmCrypto.PublicKey

  setup do
    %{
      public_key: File.read!("#{:code.priv_dir(:hm_crypto)}/demo_pub.pem"),
      private_key: File.read!("#{:code.priv_dir(:hm_crypto)}/demo_priv.pem")
    }
  end

  test "parse_pem", %{public_key: public_key, private_key: private_key} do
    parsed_public_key = HmCrypto.PublicKey.parse_pem(public_key)
    parsed_private_key = HmCrypto.PublicKey.parse_pem(private_key)

    assert parsed_public_key |> is_tuple
    assert parsed_private_key |> is_tuple

    assert parsed_public_key == HmCrypto.PublicKey.parse_pem(parsed_public_key)
    assert parsed_private_key == HmCrypto.PublicKey.parse_pem(parsed_private_key)
  end

  test "encode_pem", %{public_key: public_key, private_key: private_key} do
    parsed_public_key = HmCrypto.PublicKey.parse_pem(public_key)
    parsed_private_key = HmCrypto.PublicKey.parse_pem(private_key)

    encoded_public_key = HmCrypto.PublicKey.encode_pem(parsed_public_key)
    encoded_private_key = HmCrypto.PublicKey.encode_pem(parsed_private_key)

    assert encoded_public_key |> is_binary
    assert encoded_private_key |> is_binary

    assert parsed_public_key == HmCrypto.PublicKey.parse_pem(encoded_public_key)
    assert parsed_private_key == HmCrypto.PublicKey.parse_pem(encoded_private_key)
  end
end
