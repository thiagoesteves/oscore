defmodule OSCORE do
  @moduledoc """
  RFC 8613 (OSCORE) message protection for CoAP, with the crypto/protocol
  core implemented in Rust.

  This module handles security context derivation, message protection and
  verification, and replay-window bookkeeping. Full CoAP message framing and
  OSCORE option classification (Class E/I/U, see RFC 8613 §4.1) are the
  caller's responsibility: `inner_options` is the already-serialized CoAP
  Class E options to encrypt, and `class_i_options` is the already-serialized
  Class I options to authenticate (unencrypted).

  Only the mandatory AES-CCM-16-64-128 / HKDF-SHA-256 suite is supported.
  """

  alias OSCORE.{Context, Protected, RequestEcho}

  @typedoc "An atom describing why an OSCORE operation failed."
  @type error_reason ::
          :sequence_number_exhausted
          | :malformed_option
          | :malformed_plaintext
          | :decryption_failed
          | :unknown_kid
          | :replayed
          | :too_old

  @doc """
  Derives a Security Context (RFC 8613 §3.2) from a Master Secret and the
  Sender/Recipient IDs.

  ## Options

    * `:master_secret` (required)
    * `:sender_id` (required)
    * `:recipient_id` (required)
    * `:master_salt` - defaults to `<<>>` (the RFC 8613 default)
    * `:id_context` - defaults to `nil` (not present)

  """
  @spec derive_context(keyword()) :: {:ok, Context.t()}
  def derive_context(opts) do
    master_secret = Keyword.fetch!(opts, :master_secret)
    master_salt = Keyword.get(opts, :master_salt, <<>>)
    sender_id = Keyword.fetch!(opts, :sender_id)
    recipient_id = Keyword.fetch!(opts, :recipient_id)
    id_context = Keyword.get(opts, :id_context)

    resource =
      Oscore.Native.derive_context(
        master_secret,
        master_salt,
        sender_id,
        recipient_id,
        id_context
      )

    {:ok, %Context{resource: resource}}
  end

  @doc """
  Protects an outgoing CoAP request (RFC 8613 §8.1).

  Encrypts `code`, `inner_options`, and `payload` under a freshly
  incremented Sender Sequence Number, and returns the protected message
  along with a `RequestEcho` that must be kept around to later protect or
  verify the matching response.

  ## Options

    * `:code` (required)
    * `:inner_options` - defaults to `<<>>`
    * `:payload` - defaults to `<<>>`

  """
  @spec protect_request(Context.t(), keyword()) ::
          {:ok, Protected.t(), RequestEcho.t()} | {:error, error_reason()}
  def protect_request(%Context{resource: resource}, opts) do
    code = Keyword.fetch!(opts, :code)
    inner_options = Keyword.get(opts, :inner_options, <<>>)
    payload = Keyword.get(opts, :payload, <<>>)

    case Oscore.Native.protect_request(resource, code, inner_options, payload) do
      {:ok, {oscore_option, ciphertext, kid, piv, nonce}} ->
        {:ok, %Protected{oscore_option: oscore_option, ciphertext: ciphertext},
         %RequestEcho{kid: kid, piv: piv, nonce: nonce}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Verifies an incoming CoAP request (RFC 8613 §8.2): decrypts it and checks
  the Replay Window.

  Returns the decrypted `code`, `inner_options`, and `payload`, plus the
  `RequestEcho` needed to protect the matching response.

  ## Options

    * `:oscore_option` (required)
    * `:ciphertext` (required)
    * `:class_i_options` - defaults to `<<>>`

  """
  @spec unprotect_request(Context.t(), keyword()) ::
          {:ok, code :: byte(), inner_options :: binary(), payload :: binary(), RequestEcho.t()}
          | {:error, error_reason()}
  def unprotect_request(%Context{resource: resource}, opts) do
    oscore_option = Keyword.fetch!(opts, :oscore_option)
    ciphertext = Keyword.fetch!(opts, :ciphertext)
    class_i_options = Keyword.get(opts, :class_i_options, <<>>)

    case Oscore.Native.unprotect_request(resource, oscore_option, ciphertext, class_i_options) do
      {:ok, {code, inner_options, payload, kid, piv, nonce}} ->
        {:ok, code, inner_options, payload, %RequestEcho{kid: kid, piv: piv, nonce: nonce}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Protects an outgoing CoAP response (RFC 8613 §8.3) matching `echo`.

  By default reuses the request's AEAD nonce (no Partial IV is sent - the
  common case for a single response). Pass `partial_iv: :new` to generate a
  fresh Partial IV instead, as required for Observe notifications after the
  first one.

  ## Options

    * `:code` (required)
    * `:inner_options` - defaults to `<<>>`
    * `:payload` - defaults to `<<>>`
    * `:partial_iv` - `:reuse_request` (default) or `:new`

  """
  @spec protect_response(Context.t(), RequestEcho.t(), keyword()) ::
          {:ok, Protected.t()} | {:error, error_reason()}
  def protect_response(%Context{resource: resource}, %RequestEcho{} = echo, opts) do
    code = Keyword.fetch!(opts, :code)
    inner_options = Keyword.get(opts, :inner_options, <<>>)
    payload = Keyword.get(opts, :payload, <<>>)
    reuse_request_nonce = Keyword.get(opts, :partial_iv, :reuse_request) == :reuse_request

    case Oscore.Native.protect_response(
           resource,
           code,
           inner_options,
           payload,
           echo.kid,
           echo.piv,
           echo.nonce,
           reuse_request_nonce
         ) do
      {:ok, {oscore_option, ciphertext}} ->
        {:ok, %Protected{oscore_option: oscore_option, ciphertext: ciphertext}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Verifies an incoming CoAP response (RFC 8613 §8.4) against the
  `RequestEcho` of the request it answers.

  ## Options

    * `:oscore_option` (required)
    * `:ciphertext` (required)
    * `:class_i_options` - defaults to `<<>>`

  """
  @spec unprotect_response(Context.t(), RequestEcho.t(), keyword()) ::
          {:ok, code :: byte(), inner_options :: binary(), payload :: binary()}
          | {:error, error_reason()}
  def unprotect_response(%Context{resource: resource}, %RequestEcho{} = echo, opts) do
    oscore_option = Keyword.fetch!(opts, :oscore_option)
    ciphertext = Keyword.fetch!(opts, :ciphertext)
    class_i_options = Keyword.get(opts, :class_i_options, <<>>)

    case Oscore.Native.unprotect_response(
           resource,
           oscore_option,
           ciphertext,
           class_i_options,
           echo.kid,
           echo.piv,
           echo.nonce
         ) do
      {:ok, {code, inner_options, payload}} ->
        {:ok, code, inner_options, payload}

      {:error, reason} ->
        {:error, reason}
    end
  end
end
