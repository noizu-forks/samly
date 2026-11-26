defmodule SamlySecurityTest do
  @moduledoc """
  Regression tests for CVE-2026-53424 (assertion replay) and CVE-2026-53425
  (missing InResponseTo validation).

  Everything goes through the request handlers, so the same file runs against the
  released code (where it must fail) and against the fixed code.
  """
  use ExUnit.Case, async: false

  import Plug.Conn
  require Samly.Esaml
  alias Samly.{AuthHandler, Esaml, IdpData, SPHandler, State}

  @sp_entity "urn:sp:test"
  @consume "https://sp.example.test/sso/sp/consume/idp1"
  @request_id "id-request-1"

  defmodule FailingStore do
    def init(opts), do: opts
    def claim(_key, _expires_at, _issued_at, _opts), do: raise("store unavailable")
  end

  defmodule RefusingStore do
    def init(opts), do: opts
    def claim(_key, _expires_at, _issued_at, _opts), do: {:error, :unreachable}
  end

  setup_all do
    key = :public_key.generate_key({:rsa, 2048, 65537})
    %{cert: cert} = :public_key.pkix_test_root_cert(~c"idp", key: key)
    %{key: key, cert: cert}
  end

  setup context do
    previous = Application.get_env(:samly, Samly.ReplayStore)

    # A negative skew lets a store that has only just started accept a fresh
    # assertion. The restart test overrides it.
    store_env =
      Map.get(context, :replay_store, opts: [clock_skew: Map.get(context, :clock_skew, -3600)])

    Application.put_env(:samly, Samly.ReplayStore, store_env)

    on_exit(fn ->
      if previous,
        do: Application.put_env(:samly, Samly.ReplayStore, previous),
        else: Application.delete_env(:samly, Samly.ReplayStore)
    end)

    start_supervised!(%{id: Samly.Provider, start: {Samly.Provider, :start_link, [[]]}})

    sp =
      Esaml.esaml_sp(
        idp_signs_assertions: true,
        idp_signs_envelopes: false,
        trusted_fingerprints: [{:sha256, :crypto.hash(:sha256, context.cert)}],
        consume_uri: String.to_charlist(@consume),
        metadata_uri: ~c"https://sp.example.test/sso/sp/metadata/idp1",
        entity_id: String.to_charlist(@sp_entity)
      )

    idp = %IdpData{
      id: "idp1",
      sp_id: "sp1",
      esaml_sp_rec: sp,
      esaml_idp_rec: Esaml.esaml_idp_metadata(login_location: ~c"https://idp.example.test/sso"),
      allow_idp_initiated_flow: Map.get(context, :idp_initiated, false),
      allowed_target_urls: nil,
      use_redirect_for_req: true
    }

    %{idp: idp}
  end

  describe "CVE-2026-53424 assertion replay" do
    test "the same SP-initiated response signs in once", ctx do
      response = response(ctx, in_response_to: @request_id)

      assert consume(ctx, response).status == 302
      replay = consume(ctx, response)
      assert replay.status == 403
      assert get_session(replay, "samly_assertion_key") == nil
    end

    test "a replay with a changed unsigned Response ID is refused", ctx do
      assertion = signed_assertion(ctx, in_response_to: @request_id)

      assert consume(ctx, wrap(assertion, "_first")).status == 302
      assert consume(ctx, wrap(assertion, "_second")).status == 403
    end

    test "a replay with an added comment is refused", ctx do
      assertion = signed_assertion(ctx, in_response_to: @request_id)
      commented = String.replace(assertion, "</saml:Issuer>", "<!--c--></saml:Issuer>")
      assert commented != assertion

      assert consume(ctx, wrap(assertion)).status == 302
      assert consume(ctx, wrap(commented)).status == 403
    end

    @tag idp_initiated: true
    test "an opted-in IdP-initiated response signs in once", ctx do
      response = response(ctx, [])

      assert consume(ctx, response, %{}, "").status == 302
      assert consume(ctx, response, %{}, "").status == 403
    end

    @tag idp_initiated: true
    test "two different assertions both sign in", ctx do
      assert consume(ctx, response(ctx, id: "_a"), %{}, "").status == 302
      assert consume(ctx, response(ctx, id: "_b"), %{}, "").status == 302
    end

    @tag idp_initiated: true, clock_skew: 0
    test "an assertion issued before the replay store started is refused", ctx do
      response = response(ctx, issued: -3600)

      assert consume(ctx, response, %{}, "").status == 403
    end

    @tag replay_store: [store: FailingStore]
    test "a replay store that raises refuses the sign-in", ctx do
      assert consume(ctx, response(ctx, in_response_to: @request_id)).status == 403
    end

    @tag replay_store: [store: RefusingStore]
    test "a replay store that returns an error refuses the sign-in", ctx do
      assert consume(ctx, response(ctx, in_response_to: @request_id)).status == 403
    end
  end

  describe "CVE-2026-53425 InResponseTo validation" do
    test "a response to this session's request signs in and uses up the request ID", ctx do
      conn = consume(ctx, response(ctx, in_response_to: @request_id))

      assert conn.status == 302
      assert get_resp_header(conn, "location") == ["/home"]
      assert get_session(conn, "authn_request_id") == nil
    end

    test "a response to a different request is refused", ctx do
      conn = consume(ctx, response(ctx, in_response_to: "id-attacker-request"))

      assert conn.status == 403
      assert get_session(conn, "samly_assertion_key") == nil
      assert State.get_assertion(conn, {"idp1", "alice"}) == nil
    end

    test "a session that holds no request ID refuses a solicited response", ctx do
      session = Map.delete(sp_session(), "authn_request_id")
      conn = consume(ctx, response(ctx, in_response_to: @request_id), session)

      assert conn.status == 403
    end

    test "an unsolicited response is refused unless IdP-initiated sign-in is on", ctx do
      assert consume(ctx, response(ctx, [])).status == 403
    end

    test "the sign-in request ID is kept in the session and answers to it sign in", ctx do
      sent =
        Plug.Test.conn(:post, "/auth/signin/idp1")
        |> Plug.Test.init_test_session(%{})
        |> put_private(:samly_idp, ctx.idp)
        |> put_private(:samly_target_url, "/home")
        |> AuthHandler.send_signin_req()

      [location] = get_resp_header(sent, "location")
      query = location |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
      request = query["SAMLRequest"] |> Base.decode64!() |> :zlib.unzip()
      [_, request_id] = Regex.run(~r/<samlp:AuthnRequest[^>]*\sID="([^"]+)"/, request)

      assert get_session(sent, "authn_request_id") == request_id

      conn =
        consume(
          ctx,
          response(ctx, in_response_to: request_id),
          get_session(sent),
          get_session(sent, "relay_state")
        )

      assert conn.status == 302
    end
  end

  describe "refused payloads" do
    test "a document type declaration is refused with a 403", ctx do
      response =
        ~s(<!DOCTYPE samlp:Response SYSTEM "/nonexistent.dtd">) <>
          response(ctx, in_response_to: @request_id)

      assert consume(ctx, response).status == 403
    end
  end

  defp sp_session do
    %{
      "relay_state" => "rs-1",
      "idp_id" => "idp1",
      "target_url" => "/home",
      "authn_request_id" => @request_id
    }
  end

  defp consume(ctx, response, session \\ nil, relay_state \\ "rs-1") do
    params = %{"SAMLResponse" => Base.encode64(response), "RelayState" => relay_state}

    Plug.Test.conn(:post, "/sp/consume/idp1", params)
    |> Plug.Test.init_test_session(session || sp_session())
    |> put_private(:samly_idp, ctx.idp)
    |> SPHandler.consume_signin_response()
  end

  defp response(ctx, opts), do: wrap(signed_assertion(ctx, opts))

  defp wrap(assertion, id \\ "_response") do
    ~s(<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ) <>
      ~s(xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="#{id}" Version="2.0" ) <>
      ~s(IssueInstant="#{time(0)}"><samlp:Status><samlp:StatusCode ) <>
      ~s(Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>) <>
      assertion <> "</samlp:Response>"
  end

  defp signed_assertion(ctx, opts) do
    later = time(300)

    in_response_to =
      case opts[:in_response_to] do
        nil -> ""
        id -> ~s( InResponseTo="#{id}")
      end

    xml =
      ~s(<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ) <>
        ~s(ID="#{opts[:id] || "_assertion"}" Version="2.0" IssueInstant="#{time(opts[:issued] || 0)}">) <>
        "<saml:Issuer>https://idp.example.test</saml:Issuer>" <>
        "<saml:Subject><saml:NameID>alice</saml:NameID>" <>
        ~s(<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">) <>
        ~s(<saml:SubjectConfirmationData Recipient="#{@consume}" NotOnOrAfter="#{later}"#{in_response_to}/>) <>
        "</saml:SubjectConfirmation></saml:Subject>" <>
        ~s(<saml:Conditions NotOnOrAfter="#{later}"><saml:AudienceRestriction>) <>
        "<saml:Audience>#{@sp_entity}</saml:Audience>" <>
        "</saml:AudienceRestriction></saml:Conditions></saml:Assertion>"

    {element, _} = :xmerl_scan.string(String.to_charlist(xml), namespace_conformant: true)

    [_declaration, signed] =
      [:xmerl_dsig.sign(element, ctx.key, ctx.cert)]
      |> :xmerl.export(:xmerl_xml)
      |> :unicode.characters_to_binary()
      |> String.split("?>", parts: 2)

    signed
  end

  defp time(offset) do
    DateTime.utc_now()
    |> DateTime.add(offset, :second)
    |> DateTime.truncate(:second)
    |> DateTime.to_iso8601()
  end
end
