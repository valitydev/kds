-module(kds_ct_keyring).

-include_lib("shamir/include/shamir.hrl").

-export([init/1]).
-export([rekey/1]).
-export([lock/1]).
-export([unlock/1]).
-export([rotate/1]).

-export([decrypt_and_sign_masterkeys/3]).
-export([decrypt_and_reconstruct/3]).
-export([validate_init/2]).
-export([validate_rekey/2]).

-export([marshall_old_format/1]).

%%
%% Internal types
%%

-type config() :: [{atom(), any()}] | atom().

-spec init(config()) -> _.

init(C) ->
    EncryptedMasterKeyShares = kds_keyring_client:start_init(2, root_url(C)),
    EncPrivateKeys = enc_private_keys(C),
    SigPrivateKeys = sig_private_keys(C),
    DecryptedMasterKeyShares = decrypt_and_sign_masterkeys(EncryptedMasterKeyShares, EncPrivateKeys, SigPrivateKeys),
    ok = validate_init(DecryptedMasterKeyShares, C),
    kds_ct_utils:store(master_keys, DecryptedMasterKeyShares, C).

-spec decrypt_and_sign_masterkeys(kds_keysharing:encrypted_master_key_shares(), map(), map()) ->
    [{kds_shareholder:shareholder_id(), kds_keysharing:masterkey_share()}].

decrypt_and_sign_masterkeys(EncryptedMasterKeyShares, EncPrivateKeys, SigPrivateKeys) ->
    lists:map(
        fun
            (#{id := Id, owner := Owner, encrypted_share := EncryptedShare}) ->
                {ok, #{id := Id, owner := Owner}} = kds_shareholder:get_by_id(Id),
                EncPrivateKey = maps:get(Id, EncPrivateKeys),
                SigPrivateKey = maps:get(Id, SigPrivateKeys),
                DecryptedShare = kds_crypto:private_decrypt(EncPrivateKey, EncryptedShare),
                {Id, kds_crypto:sign(SigPrivateKey, DecryptedShare)}
        end,
        EncryptedMasterKeyShares).

-spec decrypt_and_reconstruct(kds_keysharing:encrypted_master_key_shares(), map(), integer()) ->
    kds_keysharing:masterkey().

decrypt_and_reconstruct(EncryptedMasterKeyShares, EncPrivateKeys, Threshold) ->
    {ThresholdEncryptedMasterKeyShares, _} = lists:split(Threshold, EncryptedMasterKeyShares),
    Shares = lists:foldl(
        fun (#{id := Id, encrypted_share := EncryptedShare}, Acc) ->
            EncPrivateKey = maps:get(Id, EncPrivateKeys),
            DecryptedShare = kds_crypto:private_decrypt(EncPrivateKey, EncryptedShare),
            [DecryptedShare | Acc]
        end,
        [],
        ThresholdEncryptedMasterKeyShares
    ),
    case kds_keysharing:recover(Shares) of
        {ok, MasterKey} ->
            MasterKey;
        {error, failed_to_recover} ->
            _ = logger:error("failed to recover Shares: ~p~nEncryptedMasterKeyShares: ~p",
                [Shares, EncryptedMasterKeyShares]),
            throw(recover_error)
    end.

-spec validate_init([{kds_shareholder:shareholder_id(), kds_keysharing:masterkey_share()}], config()) -> ok.

validate_init([{Id, DecryptedMasterKeyShare} | []], C) ->
    kds_keyring_client:validate_init(Id, DecryptedMasterKeyShare, root_url(C));
validate_init([{Id, DecryptedMasterKeyShare} | DecryptedMasterKeyShares], C) ->
    DecryptedMasterKeySharesCount = length(DecryptedMasterKeyShares),
    {more_keys_needed, DecryptedMasterKeySharesCount} =
        kds_keyring_client:validate_init(Id, DecryptedMasterKeyShare, root_url(C)),
    validate_init(DecryptedMasterKeyShares, C).


-spec rekey(config()) -> _.

rekey(C) ->
    ok = kds_keyring_client:start_rekey(2, root_url(C)),
    [{Id1, MasterKey1}, {Id2, MasterKey2}, _MasterKey3] = kds_ct_utils:lookup(master_keys, C),
    {more_keys_needed, 1} = kds_keyring_client:confirm_rekey(Id1, MasterKey1, root_url(C)),
    ok = kds_keyring_client:confirm_rekey(Id2, MasterKey2, root_url(C)),
    EncryptedMasterKeyShares = kds_keyring_client:start_rekey_validation(root_url(C)),
    EncPrivateKeys = enc_private_keys(C),
    SigPrivateKeys = sig_private_keys(C),
    DecryptedMasterKeyShares = decrypt_and_sign_masterkeys(EncryptedMasterKeyShares, EncPrivateKeys, SigPrivateKeys),
    ok = validate_rekey(DecryptedMasterKeyShares, C),
    kds_ct_utils:store(master_keys, DecryptedMasterKeyShares, C).

-spec validate_rekey([{kds_shareholder:shareholder_id(), kds_keysharing:masterkey_share()}], config()) -> ok.

validate_rekey([{Id, DecryptedMasterKeyShare} | []], C) ->
    kds_keyring_client:validate_rekey(Id, DecryptedMasterKeyShare, root_url(C));
validate_rekey([{Id, DecryptedMasterKeyShare} | DecryptedMasterKeyShares], C) ->
    DecryptedMasterKeySharesCount = length(DecryptedMasterKeyShares),
    {more_keys_needed, DecryptedMasterKeySharesCount} =
        kds_keyring_client:validate_rekey(Id, DecryptedMasterKeyShare, root_url(C)),
    validate_rekey(DecryptedMasterKeyShares, C).

-spec lock(config()) -> _.

lock(C) ->
    ok = kds_keyring_client:lock(root_url(C)).

-spec unlock(config()) -> _.

unlock(C) ->
    [{Id1, MasterKey1}, {Id2, MasterKey2}, _MasterKey3] = kds_ct_utils:lookup(master_keys, C),
    ok = kds_keyring_client:start_unlock(root_url(C)),
    {more_keys_needed, 1} = kds_keyring_client:confirm_unlock(Id1, MasterKey1, root_url(C)),
    ok = kds_keyring_client:confirm_unlock(Id2, MasterKey2, root_url(C)).

-spec rotate(config()) -> _.

rotate(C) ->
    [{Id1, MasterKey1}, {Id2, MasterKey2}, _MasterKey3] = kds_ct_utils:lookup(master_keys, C),
    ok = kds_keyring_client:start_rotate(root_url(C)),
    {more_keys_needed, 1} = kds_keyring_client:confirm_rotate(Id1, MasterKey1, root_url(C)),
    ok = kds_keyring_client:confirm_rotate(Id2, MasterKey2, root_url(C)).

-spec marshall_old_format(term()) -> binary().
marshall_old_format(#{current_key := CurrentKey, keys := Keys}) ->
    <<CurrentKey, (maps:fold(fun marshall_keys/3, <<>>, Keys))/binary>>.

-spec marshall_keys(byte(), binary(), binary()) -> binary().
marshall_keys(KeyId, Key, Acc) ->
    <<Acc/binary, KeyId, Key:32/binary>>.

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
