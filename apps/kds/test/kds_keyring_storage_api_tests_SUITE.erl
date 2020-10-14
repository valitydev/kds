-module(kds_keyring_storage_api_tests_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-include_lib("shamir/include/shamir.hrl").

-export([all/0]).
-export([groups/0]).
-export([init_per_group/2]).
-export([end_per_group/2]).

-export([init_check_keyring/1]).
-export([locked_unlocked_check_keyring/1]).
-export([rotation_version_check/1]).
-export([update_meta_version_check/1]).

-type config() :: [{tuple()}].

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
            init_check_keyring,
            locked_unlocked_check_keyring,
            rotation_version_check,
            update_meta_version_check
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

-spec init_check_keyring(config()) -> _.
init_check_keyring(C) ->
    _ = ?assertEqual(
        {error, {invalid_status, not_initialized}},
        get_keyring(C)
    ),
    _ = kds_ct_keyring:init(C),
    _ = ?assertMatch(
        #{
            meta := #{current_key_id := 0, version := 1, keys := #{0 := #{retired := false}}},
            data := #{keys := #{0 := _Key0}}
        },
        get_keyring(C)
    ).

-spec locked_unlocked_check_keyring(config()) -> _.
locked_unlocked_check_keyring(C) ->
    _ = ?assertMatch(
        #{
            meta := #{current_key_id := 0, version := 1, keys := #{0 := #{retired := false}}},
            data := #{keys := #{0 := _Key0}}
        },
        get_keyring(C)
    ),
    _ = kds_ct_keyring:lock(C),
    _ = ?assertEqual(
        {error, {invalid_status, locked}},
        get_keyring(C)
    ),
    _ = kds_ct_keyring:unlock(C),
    _ = ?assertMatch(
        #{
            meta := #{current_key_id := 0, version := 1, keys := #{0 := #{retired := false}}},
            data := #{keys := #{0 := _Key0}}
        },
        get_keyring(C)
    ).

-spec rotation_version_check(config()) -> _.
rotation_version_check(C) ->
    _ = ?assertMatch(
        #{
            meta := #{current_key_id := 0, version := 1, keys := #{0 := #{retired := false}}},
            data := #{keys := #{0 := _Key0}}
        },
        get_keyring(C)
    ),
    _ = kds_ct_keyring:rotate(C),
    _ = ?assertMatch(
        #{
            meta := #{
                current_key_id := 0,
                version := 2,
                keys := #{0 := #{retired := false}, 1 := #{retired := false}}
            },
            data := #{keys := #{0 := _Key0, 1 := _Key1}}
        },
        get_keyring(C)
    ).

-spec update_meta_version_check(config()) -> _.
update_meta_version_check(C) ->
    _ = ?assertMatch(
        #{
            meta := #{
                current_key_id := 0,
                version := 2,
                keys := #{0 := #{retired := false}, 1 := #{retired := false}}
            },
            data := #{keys := #{0 := _Key0, 1 := _Key1}}
        },
        get_keyring(C)
    ),
    ok = kds_keyring_client:update_keyring_meta(
        #{keys => #{0 => #{retired => true}}},
        management_root_url(C)
    ),
    _ = ?assertMatch(
        #{
            meta := #{
                current_key_id := 0,
                version := 3,
                keys := #{0 := #{retired := true}, 1 := #{retired := false}}
            },
            data := #{keys := #{0 := _Key0, 1 := _Key1}}
        },
        get_keyring(C)
    ),
    ok = kds_keyring_client:update_keyring_meta(
        #{current_key_id => 1},
        management_root_url(C)
    ),
    _ = ?assertMatch(
        #{
            meta := #{
                current_key_id := 1,
                version := 4,
                keys := #{0 := #{retired := true}, 1 := #{retired := false}}
            },
            data := #{keys := #{0 := _Key0, 1 := _Key1}}
        },
        get_keyring(C)
    ).

%%
%% internal
%%

get_keyring(C) ->
    SSLOpts = [{cacertfile, cacertfile(C)}, {certfile, clientcertfile(C)}],
    kds_keyring_client:get_keyring(storage_root_url(C), SSLOpts).

config(Key, Config) ->
    config(Key, Config, undefined).

config(Key, Config, Default) ->
    case lists:keysearch(Key, 1, Config) of
        {value, {Key, Val}} ->
            Val;
        _ ->
            Default
    end.

storage_root_url(C) ->
    config(storage_root_url, C).

management_root_url(C) ->
    config(management_root_url, C).

cacertfile(C) ->
    config(cacertfile, C).

clientcertfile(C) ->
    config(clientcertfile, C).
