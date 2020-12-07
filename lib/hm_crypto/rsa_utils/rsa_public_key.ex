defmodule HmCrypto.RsaUtils.RsaPublicKey do
  require Record
  @key_type :RSAPublicKey

  defmacro key_type, do: @key_type

  Record.defrecord(
    :record,
    @key_type,
    Record.extract(@key_type, from_lib: "public_key/include/public_key.hrl")
  )

  @type t :: record(:record, modulus: pos_integer(), publicExponent: pos_integer())
end
