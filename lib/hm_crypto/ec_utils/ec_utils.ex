defmodule HmCrypto.EcUtils do
  require HmCrypto.EcUtils.SubjectPublicKeyInfo, as: SubjectPublicKeyInfo
  require HmCrypto.EcUtils.AlgorithmIdentifier, as: AlgorithmIdentifier
  require HmCrypto.EcUtils.ECPoint, as: ECPoint
  require HmCrypto.EcUtils.ECPrivateKey, as: ECPrivateKey

  # Defined in public_key/include/OTP-PUB-KEY.hrl, no proper way to extract erlang -define values
  @id_ec_public_key {1, 2, 840, 10_045, 2, 1}

  @type crypto_curve :: :secp256k1 | :secp256r1

  @type ec_point :: {ECPoint.t(), any()}

  @doc """
    Generate EC public-private keypair. By default, SECP256K1 curve is used

    ## Examples

      iex> {public, private} = HmCrypto.EcUtils.generate_keypair()
      iex> {public, private} = HmCrypto.EcUtils.generate_keypair(:secp256k1)
  """
  @spec generate_keypair(curve_type :: crypto_curve()) ::
          {public_key :: binary(), private_key :: binary()}
  def generate_keypair(curve_type \\ :secp256k1) do
    :crypto.generate_key(:ecdh, curve_type)
  end

  @doc """
    Convert :crypto representation of EC public key (binary) to der encoded representation (binary).
    Curve must be provided explicitly since :crypto key format doesn't carry this information.

    ## Examples

      iex> {public, _private} = HmCrypto.EcUtils.generate_keypair(:secp256k1)
      iex> HmCrypto.EcUtils.crypto_pubkey_to_der(public, :secp256r1)
  """
  @spec crypto_pubkey_to_der(crypto_pubkey :: binary(), crypto_curve :: crypto_curve()) ::
          binary()
  def crypto_pubkey_to_der(crypto_pubkey, crypto_curve) do
    ecpk_params =
      :public_key.der_encode(
        :EcpkParameters,
        {:namedCurve, :pubkey_cert_records.namedCurves(crypto_curve)}
      )

    pk_info =
      SubjectPublicKeyInfo.record(
        subjectPublicKey: crypto_pubkey,
        algorithm:
          AlgorithmIdentifier.record(algorithm: @id_ec_public_key, parameters: ecpk_params)
      )

    :public_key.der_encode(:SubjectPublicKeyInfo, pk_info)
  end

  @doc """
    Convert :crypto representation of EC public key (binary) to pem encoded representation (binary).
    Curve must be provided explicitly since :crypto key format doesn't carry this information.

    ## Examples

      iex> {public, _} = HmCrypto.EcUtils.generate_keypair(:secp256k1)
      iex> HmCrypto.EcUtils.crypto_pubkey_to_pem(public, :secp256r1)
  """
  @spec crypto_pubkey_to_pem(crypto_pubkey :: binary(), crypto_curve :: crypto_curve()) ::
          String.t()
  def crypto_pubkey_to_pem(crypto_pubkey, crypto_curve) do
    crypto_public_to_ec_point(crypto_pubkey, crypto_curve)
    |> encode_pem()
  end

  @doc """
    Convert :crypto representation of EC private key (binary) to der encoded representation (binary).
    Curve must be provided explicitly since :crypto key format doesn't carry this information.

    ## Examples

      iex> {public, private} = HmCrypto.EcUtils.generate_keypair(:secp256k1)
      iex> HmCrypto.EcUtils.crypto_privkey_to_der(private, public, :secp256k1)
  """
  @spec crypto_privkey_to_der(
          crypto_privkey :: binary(),
          crypto_pubkey :: binary(),
          curve :: atom()
        ) ::
          binary()
  def crypto_privkey_to_der(crypto_privkey, crypto_pubkey, curve) do
    key_info =
      ECPrivateKey.record(
        privateKey: crypto_privkey,
        version: 1,
        parameters: {:namedCurve, :pubkey_cert_records.namedCurves(curve)},
        publicKey: crypto_pubkey
      )

    :public_key.der_encode(:ECPrivateKey, key_info)
  end

  @doc """
    Convert DER representation of EC public key (binary) to :crypto encoded representation {binary, curve_type}.

    ## Examples

      iex> {public, _private} = HmCrypto.EcUtils.generate_keypair(:secp256k1)
      iex> der_pk = HmCrypto.EcUtils.crypto_pubkey_to_der(public, :secp256r1)
      iex> {^public, _} = HmCrypto.EcUtils.der_to_crypto_pubkey(der_pk)
  """
  @spec der_to_crypto_pubkey(der_pubkey :: binary()) ::
          {crypto_pubkey :: binary(), curve :: crypto_curve()}
  def der_to_crypto_pubkey(der_pubkey) do
    SubjectPublicKeyInfo.record(
      subjectPublicKey: crypto_pubkey,
      algorithm: AlgorithmIdentifier.record(parameters: ecpk_params)
    ) = :public_key.der_decode(:SubjectPublicKeyInfo, der_pubkey)

    {:namedCurve, named_curve} = :public_key.der_decode(:EcpkParameters, ecpk_params)
    {crypto_pubkey, :pubkey_cert_records.namedCurves(named_curve)}
  end

  @doc """
    Convert PEM representation of EC public key (binary) to :crypto encoded representation {binary, curve_type}.

    ## Examples

      iex> {public, _private} = HmCrypto.EcUtils.generate_keypair(:secp256k1)
      iex> pem_pk = HmCrypto.EcUtils.crypto_pubkey_to_pem(public, :secp256r1)
      iex> {^public, _} = HmCrypto.EcUtils.pem_to_crypto_pubkey(pem_pk)
  """

  def pem_to_crypto_pubkey(pem_pubkey) do
    {ECPoint.record(point: crypto_pubkey), {:namedCurve, named_curve}} =
      HmCrypto.PublicKey.parse_pem(pem_pubkey)

    {crypto_pubkey, :pubkey_cert_records.namedCurves(named_curve)}
  end

  # For now defined only for P-256 curves
  @doc """
    Extract elliptic curve points (x and y coordinates) from :crypto public key representation

    ## Examples

      iex> {public, _private} = HmCrypto.EcUtils.generate_keypair(:secp256k1)
      iex> {x, y} = HmCrypto.EcUtils.crypto_pubkey_to_points(public)
  """
  @spec crypto_pubkey_to_points(pk_bin :: binary()) :: {x :: binary(), y :: binary}
  def crypto_pubkey_to_points(pk_bin) do
    <<_header::8, x::256, y::256>> = pk_bin
    {<<x::256>>, <<y::256>>}
  end

  @doc """
    Convert elliptic curve points (x and y coordinates) to :crypto public key representation

    ## Examples

      iex> {public, _private} = HmCrypto.EcUtils.generate_keypair(:secp256k1)
      iex> {x, y} = HmCrypto.EcUtils.crypto_pubkey_to_points(public)
      iex> ^public = HmCrypto.EcUtils.points_to_crypto_pubkey(x, y)
  """
  @spec points_to_crypto_pubkey(x :: binary(), y :: binary()) :: binary()
  def points_to_crypto_pubkey(x, y) do
    <<4::8>> <> x <> y
  end

  @doc """
    Convert der public key representation (binary) to {ECPoint record, namedCurve} format used by :public_key module

      ## Examples

      iex> {public, _} = HmCrypto.EcUtils.generate_keypair(:secp256k1)
      iex> der_pubkey = HmCrypto.EcUtils.crypto_pubkey_to_der(public, :secp256k1)
      iex> {_, _} = HmCrypto.EcUtils.der_pubkey_to_ec_point(der_pubkey)
  """
  @spec der_pubkey_to_ec_point(der_pk :: binary()) :: ec_point()
  def der_pubkey_to_ec_point(der_pk) do
    SubjectPublicKeyInfo.record(
      algorithm: AlgorithmIdentifier.record(parameters: ecpk_params),
      subjectPublicKey: public_key
    ) = :public_key.der_decode(:SubjectPublicKeyInfo, der_pk)

    named_curve = :public_key.der_decode(:EcpkParameters, ecpk_params)
    {ECPoint.record(point: public_key), named_curve}
  end

  @doc """
    Convert :crypto private key representation (binary) to ECPrivateKey record used by :public_key module

    ## Examples

      iex> {_, private_key} = HmCrypto.EcUtils.generate_keypair(:secp256k1)
      iex> _ = HmCrypto.EcUtils.crypto_secret_to_ec_private_key(private_key, :secp256k1)
  """
  @spec crypto_secret_to_ec_private_key(
          crypto_secret :: binary(),
          crypto_curve :: crypto_curve(),
          crypto_pubkey :: binary() | nil
        ) :: ECPrivateKey.t()
  def crypto_secret_to_ec_private_key(crypto_secret, crypto_curve, crypto_pubkey \\ nil) do
    ECPrivateKey.record(
      version: 1,
      privateKey: crypto_secret,
      parameters: {:namedCurve, :pubkey_cert_records.namedCurves(crypto_curve)},
      publicKey: crypto_pubkey
    )
  end

  @doc """
    Convert :crypto public key representation (binary) to ECPoint record used by :public_key module

    ## Examples

      iex> {public_key, _} = HmCrypto.EcUtils.generate_keypair(:secp256k1)
      iex> HmCrypto.EcUtils.crypto_public_to_ec_point(public_key, :secp256k1)
  """
  @spec crypto_public_to_ec_point(
          crypto_pubkey :: binary(),
          crypto_curve :: crypto_curve()
        ) :: ec_point()
  def crypto_public_to_ec_point(crypto_pubkey, crypto_curve) do
    {ECPoint.record(point: crypto_pubkey),
     {:namedCurve, :pubkey_cert_records.namedCurves(crypto_curve)}}
  end

  @doc """
    Extracts public key from private key and represents it as tuple.

    ## Examples

      iex> {public, private} = HmCrypto.EcUtils.generate_keypair(:secp256k1)
      iex> ec_privkey = HmCrypto.EcUtils.crypto_secret_to_ec_private_key(private, :secp256k1, public)
      iex> HmCrypto.EcUtils.public_key_from_private_key(ec_privkey)
  """

  @spec public_key_from_private_key(ECPrivateKey.t()) :: ec_point
  def public_key_from_private_key(
        ECPrivateKey.record(publicKey: public_key, parameters: parameters)
      ) do
    {ECPoint.record(point: public_key), parameters}
  end

  @doc """
    Extracts public key from private key pem and represents it as tuple.

    ## Examples

      iex> {public, private} = HmCrypto.EcUtils.generate_keypair(:secp256k1)
      iex> ec_privkey = HmCrypto.EcUtils.crypto_secret_to_ec_private_key(private, :secp256k1, public)
      iex> ec_privkey_pem = HmCrypto.EcUtils.encode_pem(ec_privkey)
      iex> HmCrypto.EcUtils.public_key_from_private_key_pem(ec_privkey_pem)
  """

  @spec public_key_from_private_key_pem(String.t()) :: ec_point
  def public_key_from_private_key_pem(private_key) when is_binary(private_key) do
    private_key
    |> HmCrypto.PublicKey.parse_pem()
    |> public_key_from_private_key()
  end

  @doc """
    Function encodes tuple representation of EC key to PEM format (string).
    If string is given as argument - returns it as is.

    ## Examples
      iex> {public, private} = HmCrypto.EcUtils.generate_keypair(:secp256k1)
      iex> ec_privkey = HmCrypto.EcUtils.crypto_secret_to_ec_private_key(private, :secp256k1, public)
      iex> ec_pubkey = HmCrypto.EcUtils.public_key_from_private_key(ec_privkey)
      iex> HmCrypto.EcUtils.encode_pem(ec_privkey)
      iex> pubkey_pem = HmCrypto.EcUtils.encode_pem(ec_pubkey)
      iex> HmCrypto.EcUtils.encode_pem(pubkey_pem)
  """

  @spec encode_pem(ECPrivateKey.t() | ec_point | String.t()) :: String.t()
  def encode_pem(ECPrivateKey.record() = ec_key) do
    to_pem(ECPrivateKey.key_type(), ec_key)
  end

  def encode_pem({ECPoint.record(), _} = ec_key) do
    to_pem(ECPoint.key_type(), ec_key)
  end

  def encode_pem(ec_key) when is_binary(ec_key), do: ec_key

  defp to_pem(key_type, ec_key) do
    pem_entry = [:public_key.pem_entry_encode(key_type, ec_key)]
    :public_key.pem_encode(pem_entry)
  end
end
