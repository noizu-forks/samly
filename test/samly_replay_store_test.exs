defmodule SamlyReplayStoreTest do
  use ExUnit.Case, async: false

  alias Samly.ReplayStore.ETS

  @table :samly_replay_store_test

  setup do
    opts = ETS.init(table: @table, clock_skew: 0)
    now = System.os_time(:second)
    %{opts: opts, now: now}
  end

  test "a key is claimed once", %{opts: opts, now: now} do
    assert ETS.claim("a", now + 300, now + 1, opts) == :ok
    assert ETS.claim("a", now + 300, now + 1, opts) == {:error, :replayed}
    assert ETS.claim("b", now + 300, now + 1, opts) == :ok
  end

  test "only one of many concurrent claims wins", %{opts: opts, now: now} do
    results =
      1..50
      |> Task.async_stream(fn _ -> ETS.claim("c", now + 300, now + 1, opts) end)
      |> Enum.map(fn {:ok, result} -> result end)

    assert Enum.count(results, &(&1 == :ok)) == 1
  end

  test "an assertion older than the table is refused", %{opts: opts, now: now} do
    assert ETS.claim("d", now + 300, now - 60, opts) ==
             {:error, :issued_before_replay_store_started}
  end

  test "the clock skew widens the refused window", %{opts: opts, now: now} do
    opts = %{opts | clock_skew: 60}

    assert ETS.claim("e", now + 300, now + 30, opts) ==
             {:error, :issued_before_replay_store_started}
  end

  test "a node that is connected to others refuses every claim", %{opts: opts, now: now} do
    opts = Map.put(opts, :nodes, fn -> [:other@host] end)

    assert ETS.claim("f", now + 300, now + 1, opts) == {:error, :replay_store_not_shared}
  end

  test "stale claims are removed", %{opts: opts, now: now} do
    :ets.insert(@table, {{:assertion, "old"}, now - 1})
    assert ETS.claim("g", now + 300, now + 1, opts) == :ok
    assert :ets.lookup(@table, {:assertion, "old"}) == []
  end

  test "the duplicate check refuses when no store was started" do
    Application.delete_env(:samly, :replay_store)

    assert Samly.ReplayStore.claim_assertion({}, "digest") == {:error, :replay_check_failed}
  end
end
