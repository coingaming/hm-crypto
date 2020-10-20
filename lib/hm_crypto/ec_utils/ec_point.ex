defmodule HmCrypto.EcUtils.ECPoint do
  require Record

  Record.defrecord(
    :record,
    :ECPoint,
    Record.extract(:ECPoint, from_lib: "public_key/include/public_key.hrl")
  )

  @type t :: record(:record, point: binary())
end
