defmodule HmCrypto.EcUtils.SubjectPublicKeyInfo do
  require Record

  Record.defrecord(
    :record,
    :SubjectPublicKeyInfo,
    Record.extract(:SubjectPublicKeyInfo, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  @type t ::
          record(:record,
            algorithm: HmCrypto.EcUtils.AlgorithmIdentifier.t(),
            subjectPublicKey: binary()
          )
end
