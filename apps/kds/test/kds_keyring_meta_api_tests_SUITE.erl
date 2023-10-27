-module(kds_keyring_meta_api_tests_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-include_lib("shamir/include/shamir.hrl").

-export([all/0]).
-export([groups/0]).
-export([init_per_group/2]).
-export([end_per_group/2]).

-export([init_check_meta/1]).
-export([rotate_check_meta/1]).
-export([update_meta/1]).
-export([rotate_collision_check/1]).

-type config() :: [tuple()].

-spec test() -> _.

-spec all() -> [{group, atom()}].

all() ->
    [
        {group, basic_lifecycle}
    ].

-spec groups() -> [{atom(), list(), [atom()]}].
groups() ->
    [
        {basic_lifecycle, [sequence], [
            init_check_meta,
            rotate_check_meta,
            update_meta,
            rotate_collision_check
        ]}
    ].

%%
%% starting/stopping
%%

-spec init_per_group(atom(), config()) -> config().
init_per_group(_, C) ->
    C1 = kds_ct_utils:start_stash(C),
    C2 = kds_ct_utils:start_clear(C1),
    {ok, EncPrivateKey1} = file:read_file(filename:join(config(data_dir, C2), "enc.1.priv.json")),
    {ok, EncPrivateKey2} = file:read_file(filename:join(config(data_dir, C2), "enc.2.priv.json")),
    {ok, EncPrivateKey3} = file:read_file(filename:join(config(data_dir, C2), "enc.3.priv.json")),
    EncPrivateKeys = #{<<"1">> => EncPrivateKey1, <<"2">> => EncPrivateKey2, <<"3">> => EncPrivateKey3},
    {ok, SigPrivateKey1} = file:read_file(filename:join(config(data_dir, C2), "sig.1.priv.json")),
    {ok, SigPrivateKey2} = file:read_file(filename:join(config(data_dir, C2), "sig.2.priv.json")),
    {ok, SigPrivateKey3} = file:read_file(filename:join(config(data_dir, C2), "sig.3.priv.json")),
    SigPrivateKeys = #{<<"1">> => SigPrivateKey1, <<"2">> => SigPrivateKey2, <<"3">> => SigPrivateKey3},
    [
        {enc_private_keys, EncPrivateKeys},
        {sig_private_keys, SigPrivateKeys}
    ] ++ C2.

-spec end_per_group(atom(), config()) -> _.
end_per_group(_, C) ->
    kds_ct_utils:stop_clear(C).

-spec init_check_meta(config()) -> _.
init_check_meta(C) ->
    _ = ?assertMatch(
        #{keys := #{}, current_key_id := 0},
        kds_keyring_client:get_keyring_meta(root_url(C))
    ),
    _ = ?assertMatch(
        {error, {invalid_status, not_initialized}},
        kds_keyring_client:update_keyring_meta(
            #{keys => #{0 => #{retired => true}}},
            root_url(C)
        )
    ),
    _ = ?assertMatch(
        #{keys := #{}, current_key_id := 0},
        kds_keyring_client:get_keyring_meta(root_url(C))
    ),
    _ = kds_ct_keyring:init(C),
    _ = ?assertMatch(
        #{keys := #{0 := #{retired := false}}, current_key_id := 0},
        kds_keyring_client:get_keyring_meta(root_url(C))
    ).

-spec rotate_check_meta(config()) -> _.
rotate_check_meta(C) ->
    _ = ?assertMatch(
        #{
            keys := #{
                0 := #{
                    retired := false,
                    security_parameters := #{
                        deduplication_hash_opts := #{
                            n := 16384,
                            r := 8,
                            p := 1
                        }
                    }
                }
            }
        },
        kds_keyring_client:get_keyring_meta(root_url(C))
    ),
    ok = application:set_env(kds, new_key_security_parameters, #{
        deduplication_hash_opts => #{
            n => 16384,
            r => 7,
            p => 1
        }
    }),
    _ = kds_ct_keyring:rotate(C),
    _ = ?assertMatch(
        #{
            keys := #{
                0 := #{
                    retired := false,
                    security_parameters := #{
                        deduplication_hash_opts := #{
                            n := 16384,
                            r := 8,
                            p := 1
                        }
                    }
                },
                1 := #{
                    retired := false,
                    security_parameters := #{
                        deduplication_hash_opts := #{
                            n := 16384,
                            r := 7,
                            p := 1
                        }
                    }
                }
            }
        },
        kds_keyring_client:get_keyring_meta(root_url(C))
    ).

-spec update_meta(config()) -> _.
update_meta(C) ->
    _ = ?assertMatch(
        #{
            current_key_id := 0,
            keys := #{
                0 := #{retired := false},
                1 := #{retired := false}
            }
        },
        kds_keyring_client:get_keyring_meta(root_url(C))
    ),
    ok = kds_keyring_client:update_keyring_meta(
        #{keys => #{0 => #{retired => true}}},
        root_url(C)
    ),
    ok = kds_keyring_client:update_keyring_meta(
        #{keys => #{0 => #{retired => true}}},
        root_url(C)
    ),
    _ = ?assertMatch(
        #{
            current_key_id := 0,
            keys := #{
                0 := #{retired := true},
                1 := #{retired := false}
            }
        },
        kds_keyring_client:get_keyring_meta(root_url(C))
    ),
    ok = kds_keyring_client:update_keyring_meta(
        #{current_key_id => 1},
        root_url(C)
    ),
    _ = ?assertMatch(
        #{
            current_key_id := 1,
            keys := #{
                0 := #{retired := true},
                1 := #{retired := false}
            }
        },
        kds_keyring_client:get_keyring_meta(root_url(C))
    ).

-spec rotate_collision_check(config()) -> _.
rotate_collision_check(C) ->
    [{Id1, MasterKey1}, {Id2, MasterKey2}, _MasterKey3] = kds_ct_utils:lookup(master_keys, C),
    ok = kds_keyring_client:start_rotate(root_url(C)),
    {more_keys_needed, 1} = kds_keyring_client:confirm_rotate(Id1, MasterKey1, root_url(C)),
    _ = ?assertMatch(
        #{
            current_key_id := 1,
            keys := #{
                0 := #{retired := true},
                1 := #{retired := false}
            }
        },
        kds_keyring_client:get_keyring_meta(root_url(C))
    ),
    ok = kds_keyring_client:update_keyring_meta(
        #{keys => #{0 => #{retired => false}}},
        root_url(C)
    ),
    ok = kds_keyring_client:confirm_rotate(Id2, MasterKey2, root_url(C)),
    _ = ?assertMatch(
        #{
            current_key_id := 1,
            keys := #{
                0 := #{retired := false},
                1 := #{retired := false},
                2 := #{retired := false}
            }
        },
        kds_keyring_client:get_keyring_meta(root_url(C))
    ).

%%
%% internal
%%

config(Key, Config) ->
    config(Key, Config, undefined).

config(Key, Config, Default) ->
    case lists:keysearch(Key, 1, Config) of
        {value, {Key, Val}} ->
            Val;
        _ ->
            Default
    end.

root_url(C) ->
    config(management_root_url, C).
