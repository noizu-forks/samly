defmodule Samly.ReplayStore do
  @moduledoc """
  One-time use of SAML assertions.

  Samly claims every assertion it accepts. A store must answer `:ok` for the
  first claim of a key and anything else for every later claim, until
  `expires_at`. The claim must be atomic. Any other answer, and any exception,
  refuses the sign-in.

  The default store, `Samly.ReplayStore.ETS`, holds the claims in the memory of
  one node. **Use a shared store (a database or cache with an atomic
  "insert if absent") when more than one instance can receive sign-ins**,
  including the overlap of a rolling deployment:

      config :samly, Samly.ReplayStore,
        store: MyApp.SamlReplayStore,
        opts: []
  """

  require Logger
  require Samly.Esaml

  # Seconds from year 0 (Erlang calendar) to the Unix epoch.
  @unix_epoch 62_167_219_200

  @callback init(opts :: keyword) :: term

  @doc """
  Claims `key`. `expires_at` and `issued_at` are Unix times in seconds: when the
  assertion becomes stale, and when the identity provider issued it.
  """
  @callback claim(key :: binary, expires_at :: integer, issued_at :: integer, opts :: term) ::
              :ok | {:error, term}

  @doc false
  def init do
    env = Application.get_env(:samly, __MODULE__, [])
    provider = env[:store] || Samly.ReplayStore.ETS
    opts = provider.init(env[:opts] || [])
    Application.put_env(:samly, :replay_store, %{provider: provider, opts: opts})
  end

  @doc false
  # The duplicate check that esaml calls after it has verified the assertion.
  # `digest` is the canonical digest of the signed assertion element.
  def claim_assertion(assertion_rec, digest) do
    %{provider: provider, opts: opts} = Application.fetch_env!(:samly, :replay_store)

    issued_at =
      assertion_rec
      |> Samly.Esaml.esaml_assertion(:issue_instant)
      |> :esaml_util.saml_to_datetime()
      |> :calendar.datetime_to_gregorian_seconds()

    expires_at = :esaml.stale_time(assertion_rec)

    case provider.claim(digest, expires_at - @unix_epoch, issued_at - @unix_epoch, opts) do
      :ok -> :ok
      other -> refuse(other)
    end
  catch
    kind, reason -> refuse({kind, reason})
  end

  defp refuse(reason) do
    Logger.warning("[Samly] assertion refused by the replay store: #{inspect(reason)}")
    {:error, :replay_check_failed}
  end
end
