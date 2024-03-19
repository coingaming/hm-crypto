defmodule HmCrypto.PublicKey do
  @moduledoc """
  API to work with PEM encoded keys.
  """

  @type key :: tuple() | String.t()

  @doc """
  Function parses binary (string) representation of PEM encoded key to Erlang format (tuple).
  If tuple is given as argument - returns it as is.
  """
  @spec parse_pem(key()) :: tuple()
  def parse_pem(pem_string) when is_binary(pem_string) and pem_string != "" do
    [pem_entry] = :public_key.pem_decode(pem_string)
    :public_key.pem_entry_decode(pem_entry)
  end

  def parse_pem(pem) when is_tuple(pem), do: pem
end
