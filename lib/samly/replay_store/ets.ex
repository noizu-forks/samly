defmodule Samly.ReplayStore.ETS do
  @moduledoc """
  Keeps assertion claims in an ETS table on this node. This is the default.

  The table does not survive a restart and is not shared, so the store fails
  closed where it can tell that it would miss a replay:

    * An assertion issued before the table was created (plus `:clock_skew`) is
      refused. For `:clock_skew` seconds after a start, new sign-ins are refused.
    * Every claim is refused while this node is connected to other Erlang nodes.

  It **cannot** detect instances that are not connected to each other. Use a
  shared `Samly.ReplayStore` for those.

  ## Options

    * `:table` - ETS table name (atom)
    * `:clock_skew` - seconds that the identity provider's clock may run ahead
      of this node's clock. Default `60`.
  """

  @behaviour Samly.ReplayStore

  @table :samly_replay_table
  @clock_skew 60

  @impl Samly.ReplayStore
  def init(opts) do
    table = Keyword.get(opts, :table, @table)
    clock_skew = Keyword.get(opts, :clock_skew, @clock_skew)

    if not is_atom(table) do
      raise "Samly.ReplayStore.ETS table name must be an atom: #{inspect(table)}"
    end

    if :ets.info(table) == :undefined do
      :ets.new(table, [:set, :public, :named_table])
      :ets.insert(table, {:started_at, System.os_time(:second)})
    end

    %{table: table, clock_skew: clock_skew}
  end

  @impl Samly.ReplayStore
  def claim(key, expires_at, issued_at, %{table: table, clock_skew: skew} = opts) do
    connected = Map.get(opts, :nodes, &Node.list/0)
    [{:started_at, started_at}] = :ets.lookup(table, :started_at)

    cond do
      connected.() != [] ->
        {:error, :replay_store_not_shared}

      issued_at < started_at + skew ->
        {:error, :issued_before_replay_store_started}

      true ->
        purge(table, System.os_time(:second))

        if :ets.insert_new(table, {{:assertion, key}, expires_at + max(skew, 0)}),
          do: :ok,
          else: {:error, :replayed}
    end
  end

  defp purge(table, now) do
    :ets.select_delete(table, [{{{:assertion, :_}, :"$1"}, [{:<, :"$1", now}], [true]}])
  end
end
