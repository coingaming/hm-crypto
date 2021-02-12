defmodule HmCrypto.EcUtils.ECPrivateKey do
  require Record
  @key_type :ECPrivateKey

  @spec key_type :: :ECPrivateKey
  defmacro key_type, do: @key_type

  Record.defrecord(
    :record,
    :ECPrivateKey,
    Record.extract(:ECPrivateKey, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  @type t ::
          record(:record,
            version: non_neg_integer(),
            privateKey: binary(),
            parameters: any(),
            publicKey: binary() | nil
          )
end
