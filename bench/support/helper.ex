defmodule HmCrypto.Bench.Helper do

  @key_bits_qty       [1024, 2048]
  @payload_bytes_qty  [1, 100, 100000]

  defstruct [
    :payload,
    :signature,
    :digest_type,
    :public_key,
    :private_key,
    :key_bits_qty,
    :payload_bytes_qty,
  ]

  defmacro generate_benchmarks(quoted_lambda) do

    {lambda, []} =
      Code.eval_quoted(quoted_lambda)

    payloads =
      @payload_bytes_qty
      |> Enum.reduce(%{}, fn(bytes, acc) ->
        Map.put(acc, bytes, :crypto.strong_rand_bytes(bytes))
      end)

    private_keys =
      fetch_keys("")

    public_keys =
      fetch_keys(".pub")

    HmCrypto.digest_types
    |> Enum.flat_map(fn(digest_type) ->
        private_keys
        |> Enum.flat_map(fn({key_bits_qty, private_key}) ->
          payloads
          |> Enum.map(fn({payload_bytes_qty, payload}) ->
              %__MODULE__{
                payload:            payload,
                signature:          HmCrypto.sign!(payload, digest_type, private_key),
                digest_type:        digest_type,
                public_key:         Map.get(public_keys, key_bits_qty),
                private_key:        private_key,
                key_bits_qty:       key_bits_qty,
                payload_bytes_qty:  payload_bytes_qty,
              }
          end)
        end)
    end)
    |> lambda.()
  end

  defp fetch_keys(postfix) do
    @key_bits_qty
    |> Enum.reduce(%{}, fn(bits, acc) ->
      key =
        "#{:code.priv_dir :hm_crypto}/#{bits}#{postfix}"
        |> File.read!
        |> HmCrypto.PublicKey.parse_pem
      Map.put(acc, bits, key)
    end)
  end

end
