-module(kds_keyring_sup).

-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

-spec start_link() -> {ok, pid()} | {error, Reason :: any()}.
start_link() ->
    supervisor:start_link(?MODULE, []).

-spec init(_) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init(_) ->
    ChildSpecs = [
        #{
            id => kds_keyring_manager,
            start => {kds_keyring_manager, start_link, []}
        },
        #{
            id => kds_keyring_initializer,
            start => {kds_keyring_initializer, start_link, []}
        },
        #{
            id => kds_keyring_rotator,
            start => {kds_keyring_rotator, start_link, []}
        },
        #{
            id => kds_keyring_unlocker,
            start => {kds_keyring_unlocker, start_link, []}
        },
        #{
            id => kds_keyring_rekeyer,
            start => {kds_keyring_rekeyer, start_link, []}
        }
    ],
    SupFlags = #{
        strategy => rest_for_one,
        intensity => 1,
        period => 5
    },
    {ok, {SupFlags, ChildSpecs}}.
