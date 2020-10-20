defmodule HmCrypto.EcUtils.AlgorithmIdentifier do
  require Record

  Record.defrecord(
    :record,
    :AlgorithmIdentifier,
    Record.extract(:AlgorithmIdentifier, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  @type t ::
          record(:record,
            algorithm: any(),
            parameters: any()
          )
end
