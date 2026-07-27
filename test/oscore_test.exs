defmodule OSCORETest do
  use ExUnit.Case, async: true

  alias OSCORE.{Protected, RequestEcho}

  # RFC 8613 Appendix C.1.
  @master_secret Base.decode16!("0102030405060708090a0b0c0d0e0f10", case: :lower)
  @master_salt Base.decode16!("9e7ca92223786340", case: :lower)

  defp hex(s), do: Base.decode16!(s, case: :lower)

  defp client_context do
    OSCORE.derive_context(
      master_secret: @master_secret,
      master_salt: @master_salt,
      sender_id: <<>>,
      recipient_id: hex("01")
    )
  end

  defp server_context do
    OSCORE.derive_context(
      master_secret: @master_secret,
      master_salt: @master_salt,
      sender_id: hex("01"),
      recipient_id: <<>>
    )
  end

  test "protect_request reproduces RFC 8613 Appendix C.4 bit for bit at Sender Sequence Number 20" do
    {:ok, ctx} = client_context()

    # Appendix C.4 assumes a Sender Sequence Number of 20; advance to it.
    for _ <- 1..20 do
      {:ok, _protected, _echo} =
        OSCORE.protect_request(ctx, code: 0x01, inner_options: hex("b3747631"))
    end

    {:ok, protected, echo} =
      OSCORE.protect_request(ctx, code: 0x01, inner_options: hex("b3747631"))

    assert protected.oscore_option == hex("0914")
    assert protected.ciphertext == hex("612f1092f1776f1c1668b3825e")
    assert echo.piv == hex("14")
  end

  test "full request/response round trip between independently derived client and server contexts" do
    {:ok, client} = client_context()
    {:ok, server} = server_context()

    {:ok, protected_request, client_echo} =
      OSCORE.protect_request(client, code: 0x01, inner_options: hex("b3747631"))

    {:ok, code, inner_options, payload, server_echo} =
      OSCORE.unprotect_request(server,
        oscore_option: protected_request.oscore_option,
        ciphertext: protected_request.ciphertext
      )

    assert code == 0x01
    assert inner_options == hex("b3747631")
    assert payload == <<>>
    assert server_echo.nonce == client_echo.nonce

    {:ok, protected_response} =
      OSCORE.protect_response(server, server_echo, code: 0x45, payload: "Hello World!")

    assert {:ok, 0x45, <<>>, "Hello World!"} ==
             OSCORE.unprotect_response(client, client_echo,
               oscore_option: protected_response.oscore_option,
               ciphertext: protected_response.ciphertext
             )
  end

  test "protect_response reusing the request's nonce reproduces RFC 8613 Appendix C.7 bit for bit" do
    {:ok, server} = server_context()

    request_echo = %RequestEcho{
      kid: <<>>,
      piv: hex("14"),
      nonce: hex("4622d4dd6d944168eefb549868")
    }

    {:ok, %Protected{} = protected} =
      OSCORE.protect_response(server, request_echo, code: 0x45, payload: "Hello World!")

    assert protected.oscore_option == <<>>
    assert protected.ciphertext == hex("dbaad1e9a7e7b2a813d3c31524378303cdafae119106")
  end

  test "unprotect_request rejects a replayed Partial IV" do
    {:ok, client} = client_context()
    {:ok, server} = server_context()

    {:ok, protected_request, _echo} =
      OSCORE.protect_request(client, code: 0x01, inner_options: hex("b3747631"))

    assert {:ok, _code, _opts, _payload, _echo} =
             OSCORE.unprotect_request(server,
               oscore_option: protected_request.oscore_option,
               ciphertext: protected_request.ciphertext
             )

    assert {:error, :replayed} =
             OSCORE.unprotect_request(server,
               oscore_option: protected_request.oscore_option,
               ciphertext: protected_request.ciphertext
             )
  end

  test "unprotect_request rejects a ciphertext tampered after encryption" do
    {:ok, client} = client_context()
    {:ok, server} = server_context()

    {:ok, protected_request, _echo} =
      OSCORE.protect_request(client, code: 0x01, inner_options: hex("b3747631"))

    <<first_byte, rest::binary>> = protected_request.ciphertext
    tampered_ciphertext = <<Bitwise.bxor(first_byte, 0xFF), rest::binary>>

    assert {:error, :decryption_failed} =
             OSCORE.unprotect_request(server,
               oscore_option: protected_request.oscore_option,
               ciphertext: tampered_ciphertext
             )
  end

  test "unprotect_request rejects a kid that does not match the context's Recipient ID" do
    {:ok, other_client} =
      OSCORE.derive_context(
        master_secret: @master_secret,
        master_salt: @master_salt,
        sender_id: hex("02"),
        recipient_id: hex("01")
      )

    {:ok, server} = server_context()

    {:ok, protected, _echo} =
      OSCORE.protect_request(other_client, code: 0x01, inner_options: hex("b3747631"))

    assert {:error, :unknown_kid} =
             OSCORE.unprotect_request(server,
               oscore_option: protected.oscore_option,
               ciphertext: protected.ciphertext
             )
  end
end
