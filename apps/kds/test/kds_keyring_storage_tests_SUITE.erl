-module(kds_keyring_storage_tests_SUITE).

-include_lib("common_test/include/ct.hrl").

-export([all/0]).
-export([groups/0]).
-export([init_per_group/2]).
-export([end_per_group/2]).

-export([create/1]).
-export([already_exists/1]).
-export([read/1]).
-export([update/1]).
-export([delete/1]).

-export([create_old_format/1]).
-export([read_old_format/1]).

-type config() :: [tuple()].

-spec all() -> [{group, atom()}].
all() ->
    [
        {group, file_storage_lifecycle},
        {group, backward_compatibility}
    ].

-spec groups() -> [{atom(), list(), [atom()]}].
groups() ->
    [
        {file_storage_lifecycle, [sequence], [
            create,
            already_exists,
            read,
            update,
            delete
        ]},
        {backward_compatibility, [sequence], [
            create_old_format,
            already_exists,
            read_old_format,
            update,
            delete
        ]}
    ].

%%
%% starting/stopping
%%

-spec init_per_group(atom(), config()) -> config().
init_per_group(_, C) ->
    C1 = kds_ct_utils:start_stash(C),
    kds_ct_utils:start_clear(C1).

-spec end_per_group(atom(), config()) -> config().
end_per_group(_, C) ->
    kds_ct_utils:stop_clear(C).

-spec create(config()) -> _.
create(_C) ->
    Keyring = #{data => <<"initial">>, meta => #{current_key_id => 0, version => 1, keys => #{}}},
    ok = kds_keyring_storage:create(Keyring).

-spec already_exists(config()) -> _.
already_exists(_C) ->
    Keyring = #{data => <<"bla">>, meta => #{current_key_id => 0, version => 1, keys => #{}}},
    already_exists = (catch kds_keyring_storage:create(Keyring)).

-spec read(config()) -> _.
read(_C) ->
    #{data := <<"initial">>, meta := #{current_key_id := 0, version := 1, keys := #{}}} = kds_keyring_storage:read().

-spec update(config()) -> _.
update(_C) ->
    NewKeyring = #{data => <<"updated keyring">>, meta => #{current_key_id => 0, version => 2, keys => #{}}},
    kds_keyring_storage:update(NewKeyring),
    NewKeyring = kds_keyring_storage:read().

-spec delete(config()) -> _.
delete(_C) ->
    ok = kds_keyring_storage:delete().

-spec create_old_format(config()) -> _.
create_old_format(C) ->
    KeyringStorageOpts = application:get_env(kds, keyring_storage_opts, #{}),
    KeyringPath = maps:get(keyring_path, KeyringStorageOpts, filename:join(config(priv_dir, C), "keyring")),
    ok = file:write_file(KeyringPath, <<"initial">>).

-spec read_old_format(config()) -> _.
read_old_format(_C) ->
    #{data := <<"initial">>, meta := undefined} = kds_keyring_storage:read().

config(Key, Config) ->
    config(Key, Config, undefined).

config(Key, Config, Default) ->
    case lists:keysearch(Key, 1, Config) of
        {value, {Key, Val}} ->
            Val;
        _ ->
            Default
    end.
