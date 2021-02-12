defmodule HmCrypto.EcUtils.ECPoint do
  require Record
  @key_type :SubjectPublicKeyInfo

  @spec key_type :: :SubjectPublicKeyInfo
  defmacro key_type, do: @key_type

  Record.defrecord(
    :record,
    :ECPoint,
    Record.extract(:ECPoint, from_lib: "public_key/include/public_key.hrl")
  )

  @type t :: record(:record, point: binary())
end
