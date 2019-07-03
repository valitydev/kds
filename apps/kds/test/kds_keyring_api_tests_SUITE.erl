-module(kds_keyring_api_tests_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-include_lib("shamir/include/shamir.hrl").

-export([all/0]).
-export([groups/0]).
-export([init_per_group/2]).
-export([end_per_group/2]).

-export([init/1]).
-export([init_with_timeout/1]).
-export([init_with_cancel/1]).
-export([lock/1]).
-export([unlock/1]).
-export([unlock_with_timeout/1]).
-export([rekey/1]).
-export([rekey_with_timeout/1]).
-export([rekey_with_cancel/1]).
-export([rotate/1]).
-export([rotate_with_timeout/1]).
-export([rotate_with_cancel/1]).
-export([init_invalid_status/1]).
-export([init_invalid_args/1]).
-export([init_operation_aborted_failed_to_recover/1]).
-export([init_operation_aborted_failed_to_decrypt/1]).
-export([init_operation_aborted_non_matching_mk/1]).
-export([lock_invalid_status/1]).
-export([rotate_invalid_status/1]).
-export([rekey_invalid_args/1]).
-export([rekey_invalid_status/1]).
-export([rekey_operation_aborted_failed_to_decrypt_keyring/1]).
-export([rekey_operation_aborted_failed_to_recover_confirm/1]).
-export([rekey_operation_aborted_failed_to_recover_validate/1]).
-export([rekey_operation_aborted_non_matching_masterkey/1]).
-export([rekey_operation_aborted_wrong_masterkey/1]).
-export([rotate_failed_to_recover/1]).
-export([rotate_wrong_masterkey/1]).

%%
%% tests descriptions
%%

-type config() :: [tuple()].

-spec test() -> _.

-spec all() -> [{group, atom()}].

all() ->
    [
        {group, all_groups}
    ].

-spec groups() -> [{atom(), list(), [atom()]}].

groups() ->
    [
        {all_groups, [], [
            {group, basic_lifecycle},
            {group, keyring_errors}
        ]},
        {basic_lifecycle, [sequence], [
            init,
            lock,
            unlock,
            rekey,
            rekey_with_timeout,
            rekey_with_cancel,
            rotate_with_timeout,
            lock
        ]},
        {keyring_errors, [sequence], [
            lock_invalid_status,
            init_invalid_args,
            init_with_cancel,
            init_with_timeout,
            init_operation_aborted_failed_to_recover,
            init_operation_aborted_failed_to_decrypt,
            init_operation_aborted_non_matching_mk,
            init,
            init_invalid_status,
            lock,
            lock,
            unlock_with_timeout,
            lock,
            init_invalid_status,
            rotate_invalid_status,
            rekey_invalid_status,
            unlock,
            rekey_invalid_args,
            rekey_operation_aborted_failed_to_decrypt_keyring,
            rekey_operation_aborted_failed_to_recover_confirm,
            rekey_operation_aborted_failed_to_recover_validate,
            rekey_operation_aborted_non_matching_masterkey,
            rekey_operation_aborted_wrong_masterkey,
            rotate_with_cancel,
            rotate_failed_to_recover,
            rotate_wrong_masterkey
        ]}
    ].
%%
%% starting/stopping
%%

-spec init_per_group(atom(), config()) -> config().

init_per_group(all_groups, C) ->
    C;

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

end_per_group(Group, C) when
    Group =:= all_groups
    ->
    C;

end_per_group(_, C) ->
    kds_ct_utils:stop_clear(C).

%%
%% tests
%%

-spec init(config()) -> _.

init(C) ->
    EncryptedMasterKeyShares = kds_keyring_client:start_init(2, root_url(C)),
    Shareholders = kds_shareholder:get_all(),
    _ = ?assertEqual(length(EncryptedMasterKeyShares), length(Shareholders)),
    EncPrivateKeys = enc_private_keys(C),
    SigPrivateKeys = sig_private_keys(C),
    DecryptedMasterKeyShares = kds_ct_keyring:decrypt_and_sign_masterkeys(EncryptedMasterKeyShares, EncPrivateKeys, SigPrivateKeys),
    _ = ?assertMatch(
        #{
            status := not_initialized,
            activities := #{
                initialization := #{
                    phase := validation,
                    validation_shares := #{}
                }
            }
        },
        kds_keyring_client:get_state(root_url(C))
    ),
    ok = validate_init(DecryptedMasterKeyShares, C),
    _ = ?assertMatch(
        #{
            status := unlocked,
            activities := #{
                initialization := #{
                    phase := uninitialized,
                    validation_shares := #{}
                }
            }
        },
        kds_keyring_client:get_state(root_url(C))
    ),
    kds_ct_utils:store(master_keys, DecryptedMasterKeyShares, C).

-spec init_with_timeout(config()) -> _.

init_with_timeout(C) ->
    {Id, DecryptedMasterKeyShare} = partial_init(C),
    Timeout = genlib_app:env(kds, keyring_rotation_lifetime, 4000),
    ok = timer:sleep(Timeout + 1500),
    _ = ?assertEqual(
        {error, {invalid_activity, {initialization, uninitialized}}},
        kds_keyring_client:validate_init(Id, DecryptedMasterKeyShare, root_url(C))
    ).

-spec init_with_cancel(config()) -> _.

init_with_cancel(C) ->
    {Id, DecryptedMasterKeyShare} = partial_init(C),
    ok = kds_keyring_client:cancel_init(root_url(C)),
    _ = ?assertEqual(
        {error, {invalid_activity, {initialization, uninitialized}}},
        kds_keyring_client:validate_init(Id, DecryptedMasterKeyShare, root_url(C))
    ).

partial_init(C) ->
    EncryptedMasterKeyShares = kds_keyring_client:start_init(2, root_url(C)),
    _ = ?assertEqual(
        {error, {invalid_activity, {initialization, validation}}},
        kds_keyring_client:start_init(2, root_url(C))
    ),
    Shareholders = kds_shareholder:get_all(),
    _ = ?assertEqual(length(EncryptedMasterKeyShares), length(Shareholders)),
    EncPrivateKeys = enc_private_keys(C),
    SigPrivateKeys = sig_private_keys(C),
    [{Id, DecryptedMasterKeyShare} | DecryptedMasterKeyShares] =
        kds_ct_keyring:decrypt_and_sign_masterkeys(EncryptedMasterKeyShares, EncPrivateKeys, SigPrivateKeys),
    DecryptedMasterKeySharesCount = length(DecryptedMasterKeyShares),
    _ = ?assertEqual(
        {more_keys_needed, DecryptedMasterKeySharesCount},
        kds_keyring_client:validate_init(Id, DecryptedMasterKeyShare, root_url(C))
    ),
    _ = ?assertEqual(
        {more_keys_needed, DecryptedMasterKeySharesCount},
        kds_keyring_client:validate_init(Id, DecryptedMasterKeyShare, root_url(C))
    ),
    {Id, DecryptedMasterKeyShare}.

-spec validate_init([{kds_shareholder:shareholder_id(), kds_keysharing:masterkey_share()}], config()) -> ok.

validate_init([{Id, DecryptedMasterKeyShare} | []], C) ->
    _ = ?assertEqual(
        ok,
        kds_keyring_client:validate_init(Id, DecryptedMasterKeyShare, root_url(C))
    ),
    ok;
validate_init([{Id, DecryptedMasterKeyShare} | DecryptedMasterKeyShares], C) ->
    DecryptedMasterKeySharesCount = length(DecryptedMasterKeyShares),
    _ = ?assertEqual(
        {more_keys_needed, DecryptedMasterKeySharesCount},
        kds_keyring_client:validate_init(Id, DecryptedMasterKeyShare, root_url(C))
    ),
    validate_init(DecryptedMasterKeyShares, C).

-spec lock(config()) -> _.

lock(C) ->
    ok = kds_keyring_client:lock(root_url(C)).

-spec unlock(config()) -> _.

unlock(C) ->
    _ = ?assertMatch(
        #{
            status := locked,
            activities := #{
                unlock := #{
                    phase := uninitialized
                }
            }
        },
        kds_keyring_client:get_state(root_url(C))
    ),
    [{Id1, MasterKey1}, {Id2, MasterKey2}, _MasterKey3] = kds_ct_utils:lookup(master_keys, C),
    _ = ?assertEqual(ok, kds_keyring_client:start_unlock(root_url(C))),
    _ = ?assertEqual({more_keys_needed, 1}, kds_keyring_client:confirm_unlock(Id1, MasterKey1, root_url(C))),
    _ = ?assertEqual(
        {error, {invalid_activity, {unlock, validation}}},
        kds_keyring_client:start_unlock(root_url(C))
    ),
    State = kds_keyring_client:get_state(root_url(C)),
    _ = ?assertMatch(
        #{
            status := locked,
            activities := #{
                unlock := #{
                    phase := validation
                }
            }
        },
        State
    ),
    #{activities := #{unlock := #{confirmation_shares := ConfirmationShares}}} = State,
    _ = ?assertMatch(
        #{Id1 := _},
        maps:fold(fun (K, V, Acc) -> Acc#{V => K} end, #{}, ConfirmationShares)
    ),
    _ = ?assertEqual(ok, kds_keyring_client:confirm_unlock(Id2, MasterKey2, root_url(C))).

-spec unlock_with_timeout(config()) -> _.

unlock_with_timeout(C) ->
    [{Id1, MasterKey1}, {Id2, MasterKey2}, _MasterKey3] = kds_ct_utils:lookup(master_keys, C),
    _ = ?assertEqual(ok, kds_keyring_client:start_unlock(root_url(C))),
    _ = ?assertEqual(
        {error, {invalid_activity, {unlock, validation}}},
        kds_keyring_client:start_unlock(root_url(C))
    ),
    _ = ?assertEqual({more_keys_needed, 1}, kds_keyring_client:confirm_unlock(Id1, MasterKey1, root_url(C))),
    _ = ?assertEqual({more_keys_needed, 1}, kds_keyring_client:confirm_unlock(Id1, MasterKey1, root_url(C))),
    Timeout = genlib_app:env(kds, keyring_unlock_lifetime, 1000),
    timer:sleep(Timeout + 500),
    _ = ?assertEqual(
        {error, {invalid_activity, {unlock, uninitialized}}},
        kds_keyring_client:confirm_unlock(Id1, MasterKey1, root_url(C))
    ),
    _ = ?assertEqual(ok, kds_keyring_client:start_unlock(root_url(C))),
    _ = ?assertEqual({more_keys_needed, 1}, kds_keyring_client:confirm_unlock(Id1, MasterKey1, root_url(C))),
    _ = ?assertEqual(ok, kds_keyring_client:confirm_unlock(Id2, MasterKey2, root_url(C))).

-spec rekey(config()) -> _.

rekey(C) ->
    _ = ?assertEqual(ok, kds_keyring_client:start_rekey(2, root_url(C))),
    _ = ?assertEqual(
        {error, {invalid_activity, {rekeying, confirmation}}},
        kds_keyring_client:start_rekey(2, root_url(C))
    ),
    [{Id1, MasterKey1}, {Id2, MasterKey2}, _MasterKey3] = kds_ct_utils:lookup(master_keys, C),
    _ = ?assertEqual(
        {more_keys_needed, 1},
        kds_keyring_client:confirm_rekey(Id1, MasterKey1, root_url(C))
    ),
    _ = ?assertEqual(
        {more_keys_needed, 1},
        kds_keyring_client:confirm_rekey(Id1, MasterKey1, root_url(C))
    ),
    _ = ?assertEqual(
        ok,
        kds_keyring_client:confirm_rekey(Id2, MasterKey2, root_url(C))
    ),
    _ = ?assertEqual(
        {error, {invalid_activity, {rekeying, postconfirmation}}},
        kds_keyring_client:confirm_rekey(Id2, MasterKey2, root_url(C))
    ),
    EncryptedMasterKeyShares = kds_keyring_client:start_rekey_validation(root_url(C)),
    State = kds_keyring_client:get_state(root_url(C)),
    _ = ?assertMatch(
        #{
            status := unlocked,
            activities := #{
                rekeying := #{
                    phase := validation,
                    validation_shares := #{}
                }
            }
        },
        State
    ),
    #{activities := #{rekeying := #{confirmation_shares := ConfirmationShares}}} = State,
    _ = ?assertMatch(
        #{Id1 := _, Id2 := _},
        maps:fold(fun (K, V, Acc) -> Acc#{V => K} end, #{}, ConfirmationShares)
    ),
    Shareholders = kds_shareholder:get_all(),
    _ = ?assertEqual(length(EncryptedMasterKeyShares), length(Shareholders)),
    EncPrivateKeys = enc_private_keys(C),
    SigPrivateKeys = sig_private_keys(C),
    DecryptedMasterKeyShares = kds_ct_keyring:decrypt_and_sign_masterkeys(EncryptedMasterKeyShares, EncPrivateKeys, SigPrivateKeys),
    ok = validate_rekey(DecryptedMasterKeyShares, C),
    kds_ct_utils:store(master_keys, DecryptedMasterKeyShares, C).

-spec rekey_with_timeout(config()) -> _.

rekey_with_timeout(C) ->
    _ = ?assertEqual(ok, kds_keyring_client:start_rekey(2, root_url(C))),
    [{Id1, MasterKey1}, {Id2, MasterKey2}, _MasterKey3] = kds_ct_utils:lookup(master_keys, C),
    _ = ?assertEqual(
        {more_keys_needed, 1},
        kds_keyring_client:confirm_rekey(Id1, MasterKey1, root_url(C))
    ),
    _ = ?assertEqual(
        ok,
        kds_keyring_client:confirm_rekey(Id2, MasterKey2, root_url(C))
    ),
    Timeout = genlib_app:env(kds, keyring_rekeying_lifetime, 1000),
    timer:sleep(Timeout + 500),
    _ = ?assertEqual(ok, kds_keyring_client:start_rekey(2, root_url(C))),
    _ = ?assertEqual(
        {more_keys_needed, 1},
        kds_keyring_client:confirm_rekey(Id1, MasterKey1, root_url(C))
    ),
    _ = ?assertEqual(
        ok,
        kds_keyring_client:confirm_rekey(Id2, MasterKey2, root_url(C))
    ),
    EncryptedMasterKeyShares = kds_keyring_client:start_rekey_validation(root_url(C)),
    Shareholders = kds_shareholder:get_all(),
    _ = ?assertEqual(length(EncryptedMasterKeyShares), length(Shareholders)),
    EncPrivateKeys = enc_private_keys(C),
    SigPrivateKeys = sig_private_keys(C),
    DecryptedMasterKeyShares = kds_ct_keyring:decrypt_and_sign_masterkeys(EncryptedMasterKeyShares, EncPrivateKeys, SigPrivateKeys),
    ok = validate_rekey(DecryptedMasterKeyShares, C),
    kds_ct_utils:store(master_keys, DecryptedMasterKeyShares, C).

-spec rekey_with_cancel(config()) -> _.

rekey_with_cancel(C) ->
    [{Id1, MasterKey1}, {Id2, MasterKey2}, _MasterKey3] = kds_ct_utils:lookup(master_keys, C),
    _ = ?assertEqual(
        {error, {invalid_activity, {rekeying, uninitialized}}},
        kds_keyring_client:confirm_rekey(Id1, MasterKey1, root_url(C))
    ),
    _ = ?assertEqual(ok, kds_keyring_client:start_rekey(2, root_url(C))),
    _ = ?assertEqual(ok, kds_keyring_client:cancel_rekey(root_url(C))),
    _ = ?assertEqual(ok, kds_keyring_client:start_rekey(2, root_url(C))),
    _ = ?assertEqual(
        {more_keys_needed, 1},
        kds_keyring_client:confirm_rekey(Id1, MasterKey1, root_url(C))
    ),
    _ = ?assertEqual(
        ok,
        kds_keyring_client:confirm_rekey(Id2, MasterKey2, root_url(C))
    ),
    EncryptedMasterKeyShares = kds_keyring_client:start_rekey_validation(root_url(C)),
    Shareholders = kds_shareholder:get_all(),
    _ = ?assertEqual(length(EncryptedMasterKeyShares), length(Shareholders)),
    EncPrivateKeys = enc_private_keys(C),
    SigPrivateKeys = sig_private_keys(C),
    DecryptedMasterKeyShares = kds_ct_keyring:decrypt_and_sign_masterkeys(EncryptedMasterKeyShares, EncPrivateKeys, SigPrivateKeys),
    ok = validate_rekey(DecryptedMasterKeyShares, C),
    kds_ct_utils:store(master_keys, DecryptedMasterKeyShares, C).

-spec validate_rekey([{kds_shareholder:shareholder_id(), kds_keysharing:masterkey_share()}], config()) -> ok.

validate_rekey([{Id, DecryptedMasterKeyShare} | []], C) ->
    _ = ?assertEqual(
        ok,
        kds_keyring_client:validate_rekey(Id, DecryptedMasterKeyShare, root_url(C))
    ),
    ok;
validate_rekey([{Id, DecryptedMasterKeyShare} | DecryptedMasterKeyShares], C) ->
    DecryptedMasterKeySharesCount = length(DecryptedMasterKeyShares),
    _ = ?assertEqual(
        {more_keys_needed, DecryptedMasterKeySharesCount},
        kds_keyring_client:validate_rekey(Id, DecryptedMasterKeyShare, root_url(C))
    ),
    validate_rekey(DecryptedMasterKeyShares, C).

-spec rotate(config()) -> _.

rotate(C) ->
    [{Id1, MasterKey1}, {Id2, MasterKey2}, _MasterKey3] = kds_ct_utils:lookup(master_keys, C),
    _ = ?assertEqual(
        {error, {invalid_activity, {rotation, uninitialized}}},
        kds_keyring_client:confirm_rotate(Id1, MasterKey1, root_url(C))
    ),
    _ = ?assertEqual(ok, kds_keyring_client:start_rotate(root_url(C))),
    _ = ?assertEqual(
        {error, {invalid_activity, {rotation, confirmation}}},
        kds_keyring_client:start_rotate(root_url(C))
    ),
    _ = ?assertEqual({more_keys_needed, 1}, kds_keyring_client:confirm_rotate(Id1, MasterKey1, root_url(C))),
    _ = ?assertEqual(ok, kds_keyring_client:confirm_rotate(Id2, MasterKey2, root_url(C))).

-spec rotate_with_timeout(config()) -> _.

rotate_with_timeout(C) ->
    [{Id1, MasterKey1}, {Id2, MasterKey2}, {Id3, MasterKey3}] = kds_ct_utils:lookup(master_keys, C),
    _ = ?assertEqual(ok, kds_keyring_client:start_rotate(root_url(C))),
    _ = ?assertEqual({more_keys_needed, 1}, kds_keyring_client:confirm_rotate(Id1, MasterKey1, root_url(C))),
    Timeout = genlib_app:env(kds, keyring_rotation_lifetime, 1000),
    timer:sleep(Timeout + 500),
    _ = ?assertEqual(ok, kds_keyring_client:start_rotate(root_url(C))),
    _ = ?assertEqual({more_keys_needed, 1}, kds_keyring_client:confirm_rotate(Id2, MasterKey2, root_url(C))),
    _ = ?assertEqual(ok, kds_keyring_client:confirm_rotate(Id3, MasterKey3, root_url(C))).

-spec rotate_with_cancel(config()) -> _.

rotate_with_cancel(C) ->
    [{Id1, MasterKey1}, {Id2, MasterKey2}, {Id3, MasterKey3}] = kds_ct_utils:lookup(master_keys, C),
    _ = ?assertEqual(ok, kds_keyring_client:start_rotate(root_url(C))),
    _ = ?assertEqual({more_keys_needed, 1}, kds_keyring_client:confirm_rotate(Id1, MasterKey1, root_url(C))),
    _ = ?assertEqual(ok, kds_keyring_client:cancel_rotate(root_url(C))),
    _ = ?assertEqual(ok, kds_keyring_client:start_rotate(root_url(C))),
    _ = ?assertEqual({more_keys_needed, 1}, kds_keyring_client:confirm_rotate(Id2, MasterKey2, root_url(C))),
    _ = ?assertEqual(ok, kds_keyring_client:confirm_rotate(Id3, MasterKey3, root_url(C))).

-spec init_invalid_status(config()) -> _.

init_invalid_status(C) ->
    _ = ?assertMatch(
        {error, {invalid_status, _SomeStatus}},
        kds_keyring_client:start_init(2, root_url(C))
    ).

-spec init_invalid_args(config()) -> _.

init_invalid_args(C) ->
    _ = ?assertMatch(
        {error, {invalid_arguments, _Reason}},
        kds_keyring_client:start_init(4, root_url(C))
    ),
    _ = ?assertMatch(
        {error, {invalid_arguments, _Reason}},
        kds_keyring_client:start_init(0, root_url(C))
    ).

-spec init_operation_aborted_failed_to_recover(config()) -> _.

init_operation_aborted_failed_to_recover(C) ->
    MasterKey = kds_crypto:key(),
    [WrongShare1, WrongShare2, _WrongShare3] = kds_keysharing:share(MasterKey, 2, 3),
    InvalidShare = kds_keysharing:encode_share(#share{threshold = 2, x = 4, y = <<23224>>}),
    SigPrivateKeys = sig_private_keys(C),
    [{Id1, SigPrivateKey1}, {Id2, SigPrivateKey2}, {Id3, SigPrivateKey3}] =
        maps:to_list(SigPrivateKeys),

    _ = kds_keyring_client:start_init(2, root_url(C)),
    {more_keys_needed, 2} = kds_keyring_client:validate_init(Id1, kds_crypto:sign(SigPrivateKey1, WrongShare1), root_url(C)),
    {more_keys_needed, 1} = kds_keyring_client:validate_init(Id2, kds_crypto:sign(SigPrivateKey2, WrongShare2), root_url(C)),
    _ = ?assertEqual(
        {error, {operation_aborted, <<"failed_to_recover">>}},
        kds_keyring_client:validate_init(Id3, kds_crypto:sign(SigPrivateKey3, InvalidShare), root_url(C))
    ).

-spec init_operation_aborted_failed_to_decrypt(config()) -> _.

init_operation_aborted_failed_to_decrypt(C) ->
    MasterKey = kds_crypto:key(),
    [WrongShare1, WrongShare2, WrongShare3] = kds_keysharing:share(MasterKey, 2, 3),
    SigPrivateKeys = sig_private_keys(C),
    [{Id1, SigPrivateKey1}, {Id2, SigPrivateKey2}, {Id3, SigPrivateKey3}] =
        maps:to_list(SigPrivateKeys),

    _ = kds_keyring_client:start_init(2, root_url(C)),
    {more_keys_needed, 2} = kds_keyring_client:validate_init(Id1, kds_crypto:sign(SigPrivateKey1, WrongShare1), root_url(C)),
    {more_keys_needed, 1} = kds_keyring_client:validate_init(Id2, kds_crypto:sign(SigPrivateKey2, WrongShare2), root_url(C)),
    _ = ?assertEqual(
        {error, {operation_aborted, <<"failed_to_decrypt_keyring">>}},
        kds_keyring_client:validate_init(Id3, kds_crypto:sign(SigPrivateKey3, WrongShare3), root_url(C))
    ).

-spec init_operation_aborted_non_matching_mk(config()) -> _.

init_operation_aborted_non_matching_mk(C) ->
    MasterKey = kds_crypto:key(),
    [WrongShare1, WrongShare2, _WrongShare3] = kds_keysharing:share(MasterKey, 1, 3),
    MasterKey2 = kds_crypto:key(),
    [_WrongShare4, _WrongShare5, WrongShare6] = kds_keysharing:share(MasterKey2, 1, 3),
    SigPrivateKeys = sig_private_keys(C),
    [{Id1, SigPrivateKey1}, {Id2, SigPrivateKey2}, {Id3, SigPrivateKey3}] =
        maps:to_list(SigPrivateKeys),

    _ = kds_keyring_client:start_init(1, root_url(C)),
    {more_keys_needed, 2} = kds_keyring_client:validate_init(Id1, kds_crypto:sign(SigPrivateKey1, WrongShare1), root_url(C)),
    {more_keys_needed, 1} = kds_keyring_client:validate_init(Id2, kds_crypto:sign(SigPrivateKey2, WrongShare2), root_url(C)),
    _ = ?assertEqual(
        {error, {operation_aborted, <<"non_matching_masterkey">>}},
        kds_keyring_client:validate_init(Id3, kds_crypto:sign(SigPrivateKey3, WrongShare6), root_url(C))
    ).

-spec rekey_operation_aborted_wrong_masterkey(config()) -> _.

rekey_operation_aborted_wrong_masterkey(C) ->
    MasterKey = kds_crypto:key(),
    [WrongShare1, WrongShare2, _WrongShare3] = kds_keysharing:share(MasterKey, 2, 3),
    SigPrivateKeys = sig_private_keys(C),
    [{Id1, SigPrivateKey1}, {Id2, SigPrivateKey2}, {_Id3, _SigPrivateKey3}] =
        maps:to_list(SigPrivateKeys),

    ok = kds_keyring_client:start_rekey(2, root_url(C)),
    {more_keys_needed, 1} = kds_keyring_client:confirm_rekey(Id1, kds_crypto:sign(SigPrivateKey1, WrongShare1), root_url(C)),
    {more_keys_needed, 1} = kds_keyring_client:confirm_rekey(Id1, kds_crypto:sign(SigPrivateKey1, WrongShare1), root_url(C)),
    _ = ?assertEqual(
        {error, {operation_aborted, <<"wrong_masterkey">>}},
        kds_keyring_client:confirm_rekey(Id2, kds_crypto:sign(SigPrivateKey2, WrongShare2), root_url(C))
    ).

-spec rekey_operation_aborted_failed_to_recover_confirm(config()) -> _.

rekey_operation_aborted_failed_to_recover_confirm(C) ->
    MasterKey = kds_crypto:key(),
    [WrongShare1, _WrongShare2, _WrongShare3] = kds_keysharing:share(MasterKey, 2, 3),
    InvalidShare = kds_keysharing:encode_share(#share{threshold = 2, x = 4, y = <<23224>>}),
    SigPrivateKeys = sig_private_keys(C),
    [{Id1, SigPrivateKey1}, {Id2, SigPrivateKey2}, {_Id3, _SigPrivateKey3}] =
        maps:to_list(SigPrivateKeys),

    ok = kds_keyring_client:start_rekey(2, root_url(C)),
    {more_keys_needed, 1} = kds_keyring_client:confirm_rekey(Id1, kds_crypto:sign(SigPrivateKey1, WrongShare1), root_url(C)),
    _ = ?assertEqual(
        {error, {operation_aborted, <<"failed_to_recover">>}},
        kds_keyring_client:confirm_rekey(Id2, kds_crypto:sign(SigPrivateKey2, InvalidShare), root_url(C))
    ).

-spec rekey_operation_aborted_failed_to_recover_validate(config()) -> _.

rekey_operation_aborted_failed_to_recover_validate(C) ->
    [{Id1, TrueSignedShare1}, {Id2, TrueSignedShare2}, {Id3, _TrueSignedShare3}] = kds_ct_utils:lookup(master_keys, C),
    SigPrivateKeys = sig_private_keys(C),
    #{Id1 := SigPrivateKey1, Id2 := SigPrivateKey2, Id3 := SigPrivateKey3} = SigPrivateKeys,
    MasterKey = kds_crypto:key(),
    [WrongShare1, WrongShare2, _WrongShare3] = kds_keysharing:share(MasterKey, 2, 3),
    InvalidShare = kds_keysharing:encode_share(#share{threshold = 2, x = 4, y = <<23224>>}),

    ok = kds_keyring_client:start_rekey(2, root_url(C)),
    {more_keys_needed, 1} = kds_keyring_client:confirm_rekey(Id1, TrueSignedShare1, root_url(C)),
    ok = kds_keyring_client:confirm_rekey(Id2, TrueSignedShare2, root_url(C)),
    _ = kds_keyring_client:start_rekey_validation(root_url(C)),
    {more_keys_needed, 2} = kds_keyring_client:validate_rekey(Id1, kds_crypto:sign(SigPrivateKey1, WrongShare1), root_url(C)),
    {more_keys_needed, 1} = kds_keyring_client:validate_rekey(Id2, kds_crypto:sign(SigPrivateKey2, WrongShare2), root_url(C)),
    {more_keys_needed, 1} = kds_keyring_client:validate_rekey(Id2, kds_crypto:sign(SigPrivateKey2, WrongShare2), root_url(C)),
    _ = ?assertEqual(
        {error, {operation_aborted, <<"failed_to_recover">>}},
        kds_keyring_client:validate_rekey(Id3, kds_crypto:sign(SigPrivateKey3, InvalidShare), root_url(C))
    ).

-spec rekey_operation_aborted_failed_to_decrypt_keyring(config()) -> _.

rekey_operation_aborted_failed_to_decrypt_keyring(C) ->
    [{Id1, TrueSignedShare1}, {Id2, TrueSignedShare2}, {Id3, _TrueSignedShare3}] = kds_ct_utils:lookup(master_keys, C),
    SigPrivateKeys = sig_private_keys(C),
    #{Id1 := SigPrivateKey1, Id2 := SigPrivateKey2, Id3 := SigPrivateKey3} = SigPrivateKeys,
    MasterKey = kds_crypto:key(),
    [WrongShare1, WrongShare2, WrongShare3] = kds_keysharing:share(MasterKey, 2, 3),

    ok = kds_keyring_client:start_rekey(2, root_url(C)),
    {more_keys_needed, 1} = kds_keyring_client:confirm_rekey(Id1, TrueSignedShare1, root_url(C)),
    ok = kds_keyring_client:confirm_rekey(Id2, TrueSignedShare2, root_url(C)),
    _ = kds_keyring_client:start_rekey_validation(root_url(C)),
    {more_keys_needed, 2} = kds_keyring_client:validate_rekey(Id1, kds_crypto:sign(SigPrivateKey1, WrongShare1), root_url(C)),
    {more_keys_needed, 1} = kds_keyring_client:validate_rekey(Id2, kds_crypto:sign(SigPrivateKey2, WrongShare2), root_url(C)),
    _ = ?assertEqual(
        {error, {operation_aborted, <<"failed_to_decrypt_keyring">>}},
        kds_keyring_client:validate_rekey(Id3, kds_crypto:sign(SigPrivateKey3, WrongShare3), root_url(C))
    ).


-spec rekey_operation_aborted_non_matching_masterkey(config()) -> _.

rekey_operation_aborted_non_matching_masterkey(C) ->
    [{Id1, TrueSignedShare1}, {Id2, TrueSignedShare2}, {Id3, _TrueSignedShare3}] = kds_ct_utils:lookup(master_keys, C),
    SigPrivateKeys = sig_private_keys(C),
    #{Id1 := SigPrivateKey1, Id2 := SigPrivateKey2, Id3 := SigPrivateKey3} = SigPrivateKeys,
    MasterKey = kds_crypto:key(),
    [WrongShare1, WrongShare2, _WrongShare3] = kds_keysharing:share(MasterKey, 1, 3),
    MasterKey2 = kds_crypto:key(),
    [_WrongShare4, _WrongShare5, WrongShare6] = kds_keysharing:share(MasterKey2, 1, 3),

    ok = kds_keyring_client:start_rekey(1, root_url(C)),
    {more_keys_needed, 1} = kds_keyring_client:confirm_rekey(Id1, TrueSignedShare1, root_url(C)),
    ok = kds_keyring_client:confirm_rekey(Id2, TrueSignedShare2, root_url(C)),
    _ = kds_keyring_client:start_rekey_validation(root_url(C)),
    {more_keys_needed, 2} = kds_keyring_client:validate_rekey(Id1, kds_crypto:sign(SigPrivateKey1, WrongShare1), root_url(C)),
    {more_keys_needed, 1} = kds_keyring_client:validate_rekey(Id2, kds_crypto:sign(SigPrivateKey2, WrongShare2), root_url(C)),
    _ = ?assertEqual(
        {error, {operation_aborted, <<"non_matching_masterkey">>}},
        kds_keyring_client:validate_rekey(Id3, kds_crypto:sign(SigPrivateKey3, WrongShare6), root_url(C))
    ).

-spec rekey_invalid_args(config()) -> _.

rekey_invalid_args(C) ->
    _ = ?assertMatch(
        {error, {invalid_arguments, _Reason}},
        kds_keyring_client:start_rekey(4, root_url(C))
    ),
    _ = ?assertMatch(
        {error, {invalid_arguments, _Reason}},
        kds_keyring_client:start_rekey(0, root_url(C))
    ).

-spec rekey_invalid_status(config()) -> _.

rekey_invalid_status(C) ->
    _ = ?assertMatch(
        {error, {invalid_status, _SomeStatus}},
        kds_keyring_client:start_rekey(2, root_url(C))
    ).

-spec lock_invalid_status(config()) -> _.

lock_invalid_status(C) ->
    _ = ?assertMatch(
        {error, {invalid_status, _SomeStatus}},
        kds_keyring_client:lock(root_url(C))
    ).

-spec rotate_invalid_status(config()) -> _.

rotate_invalid_status(C) ->
    _ = ?assertMatch(
        {error, {invalid_status, _SomeStatus}},
        kds_keyring_client:start_rotate(root_url(C))
    ).

-spec rotate_failed_to_recover(config()) -> _.

rotate_failed_to_recover(C) ->
    [{Id1, MasterKey1}, {Id2, _MasterKey2} | _MasterKeys] = kds_ct_utils:lookup(master_keys, C),
    MasterKey2 = kds_keysharing:encode_share(#share{threshold = 2, x = 4, y = <<23224>>}),
    SigPrivateKeys = sig_private_keys(C),
    [_SigPrivateKey1, SigPrivateKey2, _SigPrivateKey3] = maps:values(SigPrivateKeys),
    _ = ?assertEqual(
        ok,
        kds_keyring_client:start_rotate(root_url(C))
    ),
    _ = ?assertEqual(
        {error, {invalid_activity, {rotation, validation}}},
        kds_keyring_client:start_rotate(root_url(C))
    ),
    _ = ?assertEqual(
        {more_keys_needed, 1},
        kds_keyring_client:confirm_rotate(Id1, MasterKey1, root_url(C))
    ),
    _ = ?assertEqual(
        {more_keys_needed, 1},
        kds_keyring_client:confirm_rotate(Id1, MasterKey1, root_url(C))
    ),
    _ = ?assertEqual(
        {error, {operation_aborted, <<"failed_to_recover">>}},
        kds_keyring_client:confirm_rotate(Id2, kds_crypto:sign(SigPrivateKey2, MasterKey2), root_url(C))
    ).

-spec rotate_wrong_masterkey(config()) -> _.

rotate_wrong_masterkey(C) ->
    MasterKey = kds_crypto:key(),
    [MasterKey1, MasterKey2, _MasterKey3] = kds_keysharing:share(MasterKey, 2, 3),
    SigPrivateKeys = sig_private_keys(C),
    [{Id1, SigPrivateKey1}, {Id2, SigPrivateKey2}, _SigPrivateKey3] = maps:to_list(SigPrivateKeys),
    _ = ?assertEqual(
        ok,
        kds_keyring_client:start_rotate(root_url(C))
    ),
    _ = ?assertEqual(
        {more_keys_needed, 1},
        kds_keyring_client:confirm_rotate(Id1, kds_crypto:sign(SigPrivateKey1, MasterKey1), root_url(C))
    ),
    _ = ?assertEqual(
        {error, {operation_aborted, <<"wrong_masterkey">>}},
        kds_keyring_client:confirm_rotate(Id2, kds_crypto:sign(SigPrivateKey2, MasterKey2), root_url(C))
    ).

%%
%% helpers
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

enc_private_keys(C) ->
    config(enc_private_keys, C).

sig_private_keys(C) ->
    config(sig_private_keys, C).
