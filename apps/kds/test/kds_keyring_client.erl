-module(kds_keyring_client).

-include_lib("cds_proto/include/cds_proto_keyring_thrift.hrl").

-export([start_init/2]).
-export([validate_init/3]).
-export([cancel_init/1]).
-export([start_unlock/1]).
-export([confirm_unlock/3]).
-export([cancel_unlock/1]).
-export([lock/1]).
-export([start_rotate/1]).
-export([confirm_rotate/3]).
-export([cancel_rotate/1]).
-export([start_rekey/2]).
-export([confirm_rekey/3]).
-export([start_rekey_validation/1]).
-export([validate_rekey/3]).
-export([cancel_rekey/1]).
-export([get_state/1]).
-export([update_keyring_meta/2]).
-export([get_keyring_meta/1]).
-export([get_keyring/2]).

%%
%% Internal types
%%

-type encrypted_masterkey_share() :: cds_proto_keyring_thrift:'EncryptedMasterKeyShare'().

%%
%% API
%%

-spec start_init(integer(), woody:url()) ->
    [kds_keysharing:encrypted_master_key_share()] |
    {error, {invalid_status, kds_keyring_manager:state()}} |
    {error, {invalid_activity, {initialization, kds_keyring_initializer:state()}}} |
    {error, {invalid_arguments, binary()}}.
start_init(Threshold, RootUrl) ->
    try kds_woody_client:call(keyring_management, 'StartInit', [Threshold], RootUrl) of
        EncryptedShares ->
            decode_encrypted_shares(EncryptedShares)
    catch
        #'InvalidStatus'{status = Status} ->
            {error, {invalid_status, Status}};
        #'InvalidActivity'{activity = Activity} ->
            {error, {invalid_activity, Activity}};
        #'InvalidArguments'{reason = Reason} ->
            {error, {invalid_arguments, Reason}}
    end.

-spec validate_init(kds_shareholder:shareholder_id(), kds_keysharing:masterkey_share(), woody:url()) ->
    ok | {more_keys_needed, non_neg_integer()} |
    {error, {invalid_status, kds_keyring_manager:state()}} |
    {error, {invalid_activity, {initialization, kds_keyring_initializer:state()}}} |
    {error, verification_failed} |
    {error, {invalid_arguments, binary()}}.
validate_init(ShareholderId, Share, RootUrl) ->
    try kds_woody_client:call(keyring_management, 'ValidateInit', [ShareholderId, Share], RootUrl) of
        {success, #'Success'{}} ->
            ok;
        {more_keys_needed, More} ->
            {more_keys_needed, More}
    catch
        #'InvalidStatus'{status = Status} ->
            {error, {invalid_status, Status}};
        #'InvalidActivity'{activity = Activity} ->
            {error, {invalid_activity, Activity}};
        #'VerificationFailed'{} ->
            {error, verification_failed};
        #'OperationAborted'{reason = Reason} ->
            {error, {operation_aborted, Reason}}
    end.

-spec cancel_init(woody:url()) ->
    ok |
    {error, {invalid_status, kds_keyring_manager:state()}} |
    {error, {invalid_activity, {initialization, kds_keyring_initializer:state()}}}.
cancel_init(RootUrl) ->
    try kds_woody_client:call(keyring_management, 'CancelInit', [], RootUrl) catch
        #'InvalidStatus'{status = Status} ->
            {error, {invalid_status, Status}};
        #'InvalidActivity'{activity = Activity} ->
            {error, {invalid_activity, Activity}}
    end.

-spec start_unlock(woody:url()) ->
    ok |
    {error, {invalid_status, kds_keyring_manager:state()}} |
    {error, {invalid_activity, {unlock, kds_keyring_unlocker:state()}}}.
start_unlock(RootUrl) ->
    try kds_woody_client:call(keyring_management, 'StartUnlock', [], RootUrl) catch
        #'InvalidStatus'{status = Status} ->
            {error, {invalid_status, Status}};
        #'InvalidActivity'{activity = Activity} ->
            {error, {invalid_activity, Activity}}
    end.

-spec confirm_unlock(kds_shareholder:shareholder_id(), kds_keysharing:masterkey_share(), woody:url()) ->
    ok | {more_keys_needed, non_neg_integer()} |
    {error, {invalid_status, kds_keyring_manager:state()}} |
    {error, {invalid_activity, {unlock, kds_keyring_unlocker:state()}}} |
    {error, verification_failed} |
    {error, {operation_aborted, binary()}}.
confirm_unlock(ShareholderId, Share, RootUrl) ->
    try kds_woody_client:call(keyring_management, 'ConfirmUnlock', [ShareholderId, Share], RootUrl) of
        {success, #'Success'{}} ->
            ok;
        {more_keys_needed, More} ->
            {more_keys_needed, More}
    catch
        #'InvalidStatus'{status = Status} ->
            {error, {invalid_status, Status}};
        #'InvalidActivity'{activity = Activity} ->
            {error, {invalid_activity, Activity}};
        #'VerificationFailed'{} ->
            {error, verification_failed};
        #'OperationAborted'{reason = Reason} ->
            {error, {operation_aborted, Reason}}
    end.

-spec cancel_unlock(woody:url()) ->
    ok |
    {error, {invalid_status, kds_keyring_manager:state()}}.
cancel_unlock(RootUrl) ->
    try kds_woody_client:call(keyring_management, 'CancelUnlock', [], RootUrl) catch
        #'InvalidStatus'{status = Status} ->
            {error, {invalid_status, Status}}
    end.

-spec lock(woody:url()) ->
    ok |
    {error, {invalid_status, kds_keyring_manager:state()}}.
lock(RootUrl) ->
    try kds_woody_client:call(keyring_management, 'Lock', [], RootUrl) catch
        #'InvalidStatus'{status = Status} ->
            {error, {invalid_status, Status}}
    end.

-spec start_rotate(woody:url()) ->
    ok |
    {error, {invalid_status, kds_keyring_manager:state()}} |
    {error, {invalid_activity, {rotation, kds_keyring_rotator:state()}}}.
start_rotate(RootUrl) ->
    try kds_woody_client:call(keyring_management, 'StartRotate', [], RootUrl) catch
        #'InvalidStatus'{status = Status} ->
            {error, {invalid_status, Status}};
        #'InvalidActivity'{activity = Activity} ->
            {error, {invalid_activity, Activity}}
    end.

-spec confirm_rotate(kds_shareholder:shareholder_id(), kds_keysharing:masterkey_share(), woody:url()) ->
    ok | {more_keys_needed, non_neg_integer()} |
    {error, {invalid_status, kds_keyring_manager:state()}} |
    {error, {invalid_activity, {rotation, kds_keyring_rotator:state()}}} |
    {error, verification_failed} |
    {error, {operation_aborted, binary()}}.
confirm_rotate(ShareholderId, Share, RootUrl) ->
    try kds_woody_client:call(keyring_management, 'ConfirmRotate', [ShareholderId, Share], RootUrl) of
        {success, #'Success'{}} ->
            ok;
        {more_keys_needed, More} ->
            {more_keys_needed, More}
    catch
        #'InvalidStatus'{status = Status} ->
            {error, {invalid_status, Status}};
        #'InvalidActivity'{activity = Activity} ->
            {error, {invalid_activity, Activity}};
        #'VerificationFailed'{} ->
            {error, verification_failed};
        #'OperationAborted'{reason = Reason} ->
            {error, {operation_aborted, Reason}}
    end.

-spec cancel_rotate(woody:url()) ->
    ok |
    {error, {invalid_status, kds_keyring_manager:state()}}.
cancel_rotate(RootUrl) ->
    try kds_woody_client:call(keyring_management, 'CancelRotate', [], RootUrl) catch
        #'InvalidStatus'{status = Status} ->
            {error, {invalid_status, Status}}
    end.

-spec start_rekey(integer(), woody:url()) ->
    ok |
    {error, {invalid_status, kds_keyring_manager:state()}} |
    {error, {invalid_activity, {rekeying, kds_keyring_rotator:state()}}} |
    {error, {invalid_arguments, binary()}}.
start_rekey(Threshold, RootUrl) ->
    try kds_woody_client:call(keyring_management, 'StartRekey', [Threshold], RootUrl) catch
        #'InvalidStatus'{status = Status} ->
            {error, {invalid_status, Status}};
        #'InvalidActivity'{activity = Activity} ->
            {error, {invalid_activity, Activity}};
        #'InvalidArguments'{reason = Reason} ->
            {error, {invalid_arguments, Reason}}
    end.

-spec confirm_rekey(kds_shareholder:shareholder_id(), kds_keysharing:masterkey_share(), woody:url()) ->
    ok | {more_keys_needed, non_neg_integer()} |
    {error, {invalid_status, kds_keyring_manager:state()}} |
    {error, {invalid_activity, {rekeying, kds_keyring_rotator:state()}}} |
    {error, verification_failed} |
    {error, {operation_aborted, binary()}}.
confirm_rekey(ShareholderId, Share, RootUrl) ->
    try kds_woody_client:call(keyring_management, 'ConfirmRekey', [ShareholderId, Share], RootUrl) of
        {success, #'Success'{}} ->
            ok;
        {more_keys_needed, More} ->
            {more_keys_needed, More}
    catch
        #'InvalidStatus'{status = Status} ->
            {error, {invalid_status, Status}};
        #'InvalidActivity'{activity = Activity} ->
            {error, {invalid_activity, Activity}};
        #'VerificationFailed'{} ->
            {error, verification_failed};
        #'OperationAborted'{reason = Reason} ->
            {error, {operation_aborted, Reason}}
    end.

-spec start_rekey_validation(woody:url()) ->
    [kds_keysharing:encrypted_master_key_share()] |
    {error, {invalid_status, kds_keyring_manager:state()}} |
    {error, {invalid_activity, {rekeying, kds_keyring_rotator:state()}}}.
start_rekey_validation(RootUrl) ->
    try kds_woody_client:call(keyring_management, 'StartRekeyValidation', [], RootUrl) of
        EncryptedShares ->
            decode_encrypted_shares(EncryptedShares)
    catch
        #'InvalidStatus'{status = Status} ->
            {error, {invalid_status, Status}};
        #'InvalidActivity'{activity = Activity} ->
            {error, {invalid_activity, Activity}}
    end.

-spec validate_rekey(kds_shareholder:shareholder_id(), kds_keysharing:masterkey_share(), woody:url()) ->
    ok | {more_keys_needed, non_neg_integer()} |
    {error, {invalid_status, kds_keyring_manager:state()}} |
    {error, {invalid_activity, {rekeying, kds_keyring_rotator:state()}}} |
    {error, verification_failed} |
    {error, {operation_aborted, binary()}}.
validate_rekey(ShareholderId, Share, RootUrl) ->
    try kds_woody_client:call(keyring_management, 'ValidateRekey', [ShareholderId, Share], RootUrl) of
        {success, #'Success'{}} ->
            ok;
        {more_keys_needed, More} ->
            {more_keys_needed, More}
    catch
        #'InvalidStatus'{status = Status} ->
            {error, {invalid_status, Status}};
        #'InvalidActivity'{activity = Activity} ->
            {error, {invalid_activity, Activity}};
        #'VerificationFailed'{} ->
            {error, verification_failed};
        #'OperationAborted'{reason = Reason} ->
            {error, {operation_aborted, Reason}}
    end.

-spec cancel_rekey(woody:url()) ->
    ok |
    {error, {invalid_status, kds_keyring_manager:state()}}.
cancel_rekey(RootUrl) ->
    try kds_woody_client:call(keyring_management, 'CancelRekey', [], RootUrl)
    catch
        #'InvalidStatus'{status = Status} ->
            {error, {invalid_status, Status}}
    end.

-spec get_state(woody:url()) -> kds_keyring_manager:status().
get_state(RootUrl) ->
    State = kds_woody_client:call(keyring_management, 'GetState', [], RootUrl),
    decode_state(State).

-spec update_keyring_meta(kds_keyring_meta:keyring_meta(), woody:url()) ->
    ok |
    {error, {invalid_keyring_meta, binary()}} |
    {error, {invalid_status, kds_keyring_manager:state()}}.
update_keyring_meta(KeyringMeta, RootUrl) ->
    try
        EncodedMeta = kds_keyring_meta:encode_keyring_meta_diff(KeyringMeta),
        kds_woody_client:call(keyring_management, 'UpdateKeyringMeta', [EncodedMeta], RootUrl)
    catch
        #'InvalidKeyringMeta'{reason = Reason} ->
            {error, {invalid_keyring_meta, Reason}};
        #'InvalidStatus'{status = Status} ->
            {error, {invalid_status, Status}}
    end.

-spec get_keyring_meta(woody:url()) -> kds_keyring_meta:keyring_meta().
get_keyring_meta(RootUrl) ->
    KeyringMeta = kds_woody_client:call(keyring_management, 'GetKeyringMeta', [], RootUrl),
    kds_keyring_meta:decode_keyring_meta(KeyringMeta).

-spec get_keyring(woody:url(), term()) -> kds_keyring:keyring().
get_keyring(RootUrl, SSLOptions) ->
    ExtraOpts = #{
        transport_opts => #{
            ssl_options => [
                {server_name_indication, "Test Server"},
                {verify, verify_peer} |
                SSLOptions
            ]
        }
    },
    try kds_woody_client:call(keyring_storage, 'GetKeyring', [], RootUrl, ExtraOpts) of
        Keyring ->
            decode_keyring(Keyring)
    catch
        #'InvalidStatus'{status = Status} ->
            {error, {invalid_status, Status}}
    end.

decode_state(#'KeyringState'{
    status = Status,
    activities = #'ActivitiesState'{
        initialization =  #'InitializationState'{
            phase = InitPhase,
            lifetime = InitLifetime,
            validation_shares = InitValShares
        },
        unlock = #'UnlockState'{
            phase = UnlockPhase,
            lifetime = UnlockLifetime,
            confirmation_shares = UnlockConShares
        },
        rotation = #'RotationState'{
            phase = RotatePhase,
            lifetime = RotateLifetime,
            confirmation_shares = RotateConShares
        },
        rekeying = #'RekeyingState'{
            phase = RekeyPhase,
            lifetime = RekeyLifetime,
            confirmation_shares = RekeyConShares,
            validation_shares = RekeyValShares
        }
    }
}) ->
    #{
        status => Status,
        activities => #{
            initialization => #{
                phase => InitPhase,
                lifetime => InitLifetime,
                validation_shares => InitValShares
            },
            unlock => #{
                phase => UnlockPhase,
                lifetime => UnlockLifetime,
                confirmation_shares => UnlockConShares
            },
            rotation => #{
                phase => RotatePhase,
                lifetime => RotateLifetime,
                confirmation_shares => RotateConShares
            },
            rekeying => #{
                phase => RekeyPhase,
                lifetime => RekeyLifetime,
                confirmation_shares => RekeyConShares,
                validation_shares => RekeyValShares
            }
        }
    }.

-spec decode_encrypted_shares([encrypted_masterkey_share()]) ->
    [kds_keysharing:encrypted_master_key_share()].

decode_encrypted_shares(EncryptedMasterKeyShares) ->
    lists:map(fun decode_encrypted_share/1, EncryptedMasterKeyShares).

-spec decode_encrypted_share(encrypted_masterkey_share()) ->
    kds_keysharing:encrypted_master_key_share().

decode_encrypted_share(#'EncryptedMasterKeyShare' {
    id = Id,
    owner = Owner,
    encrypted_share = EncryptedShare
}) ->
    #{
        id => Id,
        owner => Owner,
        encrypted_share => EncryptedShare
    }.

decode_keyring(#'Keyring'{
    version = Version,
    current_key_id = CurrentKeyId,
    keys = Keys
}) ->
    #{
        data => #{
            keys => decode_keys(Keys)
        },
        meta => #{
            current_key_id => CurrentKeyId,
            version => Version,
            keys => decode_keys_meta(Keys)
        }
    }.

decode_keys(Keys) ->
    maps:fold(
        fun (K, #'Key'{data = KeyData}, Acc) ->
            Acc#{K => KeyData}
        end,
        #{},
        Keys
    ).

decode_keys_meta(Keys) ->
    maps:fold(
        fun (K, #'Key'{meta = #'KeyMeta'{retired = Retired}}, Acc) ->
            Acc#{K => #{retired => Retired}}
        end,
        #{},
        Keys
    ).
