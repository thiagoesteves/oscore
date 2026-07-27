defmodule OSCORE.Context do
  @moduledoc """
  A derived RFC 8613 Security Context (§3.1): Sender/Recipient keys and the
  Common IV, plus (native-side) the mutable Sender Sequence Number and
  Recipient replay window.

  Opaque - build one with `OSCORE.derive_context/1`.
  """

  @enforce_keys [:resource]
  defstruct [:resource]

  @type t :: %__MODULE__{resource: reference()}
end

defmodule OSCORE.RequestEcho do
  @moduledoc """
  The `kid`, Partial IV, and AEAD nonce of a protected request (RFC 8613
  §5.4), needed to later protect or verify its matching response.
  """

  @enforce_keys [:kid, :piv, :nonce]
  defstruct [:kid, :piv, :nonce]

  @type t :: %__MODULE__{kid: binary(), piv: binary(), nonce: binary()}
end

defmodule OSCORE.Protected do
  @moduledoc """
  An OSCORE-protected message: the OSCORE option value and ciphertext to
  carry in the OSCORE option and payload of the outgoing CoAP message.
  """

  @enforce_keys [:oscore_option, :ciphertext]
  defstruct [:oscore_option, :ciphertext]

  @type t :: %__MODULE__{oscore_option: binary(), ciphertext: binary()}
end
