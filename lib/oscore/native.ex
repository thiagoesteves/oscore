defmodule Oscore.Native do
  @moduledoc false

  use Rustler, otp_app: :oscore, crate: "oscore_nif"

  def derive_context(_master_secret, _master_salt, _sender_id, _recipient_id, _id_context),
    do: error()

  def protect_request(_ctx, _code, _inner_options, _payload), do: error()

  def unprotect_request(_ctx, _oscore_option, _ciphertext, _class_i_options), do: error()

  def protect_response(
        _ctx,
        _code,
        _inner_options,
        _payload,
        _request_kid,
        _request_piv,
        _request_nonce,
        _reuse_request_nonce
      ),
      do: error()

  def unprotect_response(
        _ctx,
        _oscore_option,
        _ciphertext,
        _class_i_options,
        _request_kid,
        _request_piv,
        _request_nonce
      ),
      do: error()

  defp error, do: :erlang.nif_error(:nif_not_loaded)
end
