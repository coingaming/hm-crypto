defmodule HmCrypto.RsaUtils.RsaPrivateKey do
  require Record
  @key_type :RSAPrivateKey

  defmacro key_type, do: @key_type

  Record.defrecord(
    :record,
    @key_type,
    Record.extract(@key_type, from_lib: "public_key/include/public_key.hrl")
  )

  @type t ::
          record(
            :record,
            version: atom(),
            modulus: pos_integer(),
            publicExponent: pos_integer(),
            privateExponent: pos_integer(),
            prime1: pos_integer(),
            prime2: pos_integer(),
            exponent1: pos_integer(),
            exponent2: pos_integer(),
            coefficient: pos_integer(),
            otherPrimeInfos: atom()
          )
end
