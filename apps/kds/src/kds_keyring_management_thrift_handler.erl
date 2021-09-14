-module(kds_keyring_management_thrift_handler).

-behaviour(woody_server_thrift_handler).

-include_lib("cds_proto/include/cds_proto_keyring_thrift.hrl").

%% woody_server_thrift_handler callbacks
-export([handle_function/4]).

-type encrypted_masterkey_share() :: #cds_EncryptedMasterKeyShare{}.

%%
%% woody_server_thrift_handler callbacks
%%

-spec handle_function(woody:func(), woody:args(), woody_context:ctx(), woody:options()) ->
    {ok, woody:result()} | no_return().
handle_function(OperationID, Args, Context, Opts) ->
    scoper:scope(
        keyring_management,
        kds_thrift_handler_utils:filter_fun_exceptions(
            fun() ->
                handle_function_(OperationID, Args, Context, Opts)
            end
        )
    ).

handle_function_('StartInit', {Threshold}, _Context, _Opts) ->
    try kds_keyring_manager:initialize(Threshold) of
        EncryptedMasterKeyShares ->
            {ok, encode_encrypted_shares(EncryptedMasterKeyShares)}
    catch
        {invalid_status, Status} ->
            raise(#cds_InvalidStatus{status = Status});
        {invalid_activity, Activity} ->
            raise(#cds_InvalidActivity{activity = Activity});
        invalid_args ->
            raise(#cds_InvalidArguments{})
    end;
handle_function_('ValidateInit', {SignedShare}, _Context, _Opts) ->
    {ShareholderId, Share} = decode_signed_share(SignedShare),
    VerifiedShare = verify_signed_share(ShareholderId, Share, 'ValidateInit'),
    try kds_keyring_manager:validate_init(ShareholderId, VerifiedShare) of
        {more, More} ->
            {ok, {more_keys_needed, More}};
        ok ->
            {ok, {success, #cds_Success{}}}
    catch
        {invalid_status, Status} ->
            raise(#cds_InvalidStatus{status = Status});
        {invalid_activity, Activity} ->
            raise(#cds_InvalidActivity{activity = Activity});
        {operation_aborted, Reason} ->
            raise(#cds_OperationAborted{reason = atom_to_binary(Reason, utf8)})
    end;
handle_function_('CancelInit', {}, _Context, _Opts) ->
    try
        {ok, kds_keyring_manager:cancel_init()}
    catch
        {invalid_status, Status} ->
            raise(#cds_InvalidStatus{status = Status})
    end;
handle_function_('Lock', {}, _Context, _Opts) ->
    try
        {ok, kds_keyring_manager:lock()}
    catch
        {invalid_status, locked} ->
            {ok, ok};
        {invalid_status, Status} ->
            raise(#cds_InvalidStatus{status = Status})
    end;
handle_function_('StartUnlock', {}, _Context, _Opts) ->
    try
        {ok, kds_keyring_manager:start_unlock()}
    catch
        {invalid_status, Status} ->
            raise(#cds_InvalidStatus{status = Status});
        {invalid_activity, Activity} ->
            raise(#cds_InvalidActivity{activity = Activity})
    end;
handle_function_('ConfirmUnlock', {SignedShare}, _Context, _Opts) ->
    {ShareholderId, Share} = decode_signed_share(SignedShare),
    VerifiedShare = verify_signed_share(ShareholderId, Share, 'ConfirmUnlock'),
    try kds_keyring_manager:confirm_unlock(ShareholderId, VerifiedShare) of
        {more, More} ->
            {ok, {more_keys_needed, More}};
        ok ->
            {ok, {success, #cds_Success{}}}
    catch
        {invalid_status, Status} ->
            raise(#cds_InvalidStatus{status = Status});
        {invalid_activity, Activity} ->
            raise(#cds_InvalidActivity{activity = Activity});
        {operation_aborted, Reason} ->
            raise(#cds_OperationAborted{reason = atom_to_binary(Reason, utf8)})
    end;
handle_function_('CancelUnlock', {}, _Context, _Opts) ->
    try
        {ok, kds_keyring_manager:cancel_unlock()}
    catch
        {invalid_status, Status} ->
            raise(#cds_InvalidStatus{status = Status})
    end;
handle_function_('StartRotate', {}, _Context, _Opts) ->
    try
        {ok, kds_keyring_manager:start_rotate()}
    catch
        {invalid_status, Status} ->
            raise(#cds_InvalidStatus{status = Status});
        {invalid_activity, Activity} ->
            raise(#cds_InvalidActivity{activity = Activity})
    end;
handle_function_('ConfirmRotate', {SignedShare}, _Context, _Opts) ->
    {ShareholderId, Share} = decode_signed_share(SignedShare),
    VerifiedShare = verify_signed_share(ShareholderId, Share, 'ConfirmRotate'),
    try kds_keyring_manager:confirm_rotate(ShareholderId, VerifiedShare) of
        {more, More} ->
            {ok, {more_keys_needed, More}};
        ok ->
            {ok, {success, #cds_Success{}}}
    catch
        {invalid_status, Status} ->
            raise(#cds_InvalidStatus{status = Status});
        {invalid_activity, Activity} ->
            raise(#cds_InvalidActivity{activity = Activity});
        {operation_aborted, Reason} ->
            raise(#cds_OperationAborted{reason = atom_to_binary(Reason, utf8)})
    end;
handle_function_('CancelRotate', {}, _Context, _Opts) ->
    try
        {ok, kds_keyring_manager:cancel_rotate()}
    catch
        {invalid_status, Status} ->
            raise(#cds_InvalidStatus{status = Status})
    end;
handle_function_('StartRekey', {Threshold}, _Context, _Opts) ->
    try
        {ok, kds_keyring_manager:start_rekey(Threshold)}
    catch
        {invalid_status, Status} ->
            raise(#cds_InvalidStatus{status = Status});
        {invalid_activity, Activity} ->
            raise(#cds_InvalidActivity{activity = Activity});
        invalid_args ->
            raise(#cds_InvalidArguments{})
    end;
handle_function_('ConfirmRekey', {SignedShare}, _Context, _Opts) ->
    {ShareholderId, Share} = decode_signed_share(SignedShare),
    VerifiedShare = verify_signed_share(ShareholderId, Share, 'ConfirmRekey'),
    try kds_keyring_manager:confirm_rekey(ShareholderId, VerifiedShare) of
        {more, More} ->
            {ok, {more_keys_needed, More}};
        ok ->
            {ok, {success, #cds_Success{}}}
    catch
        {invalid_status, Status} ->
            raise(#cds_InvalidStatus{status = Status});
        {invalid_activity, Activity} ->
            raise(#cds_InvalidActivity{activity = Activity});
        {operation_aborted, Reason} ->
            raise(#cds_OperationAborted{reason = atom_to_binary(Reason, utf8)})
    end;
handle_function_('StartRekeyValidation', {}, _Context, _Opts) ->
    try kds_keyring_manager:start_validate_rekey() of
        EncryptedMasterKeyShares ->
            {ok, encode_encrypted_shares(EncryptedMasterKeyShares)}
    catch
        {invalid_status, Status} ->
            raise(#cds_InvalidStatus{status = Status});
        {invalid_activity, Activity} ->
            raise(#cds_InvalidActivity{activity = Activity})
    end;
handle_function_('ValidateRekey', {SignedShare}, _Context, _Opts) ->
    {ShareholderId, Share} = decode_signed_share(SignedShare),
    VerifiedShare = verify_signed_share(ShareholderId, Share, 'ValidateRekey'),
    try kds_keyring_manager:validate_rekey(ShareholderId, VerifiedShare) of
        {more, More} ->
            {ok, {more_keys_needed, More}};
        ok ->
            {ok, {success, #cds_Success{}}}
    catch
        {invalid_status, Status} ->
            raise(#cds_InvalidStatus{status = Status});
        {invalid_activity, Activity} ->
            raise(#cds_InvalidActivity{activity = Activity});
        {operation_aborted, Reason} ->
            raise(#cds_OperationAborted{reason = atom_to_binary(Reason, utf8)})
    end;
handle_function_('CancelRekey', {}, _Context, _Opts) ->
    try
        {ok, kds_keyring_manager:cancel_rekey()}
    catch
        {invalid_status, Status} ->
            raise(#cds_InvalidStatus{status = Status})
    end;
handle_function_('GetState', {}, _Context, _Opts) ->
    case kds_keyring_manager:get_status() of
        Status ->
            {ok, encode_state(Status)}
    end;
handle_function_('UpdateKeyringMeta', {KeyringMeta}, _Context, _Opts) ->
    try
        DecodedKeyringMeta = kds_keyring_meta:decode_keyring_meta_diff(KeyringMeta),
        kds_keyring_manager:update_meta(DecodedKeyringMeta)
    of
        ok ->
            {ok, ok}
    catch
        {invalid_status, Status} ->
            raise(#cds_InvalidStatus{status = Status});
        {validation_failed, Reason} ->
            raise(#cds_InvalidKeyringMeta{reason = erlang:atom_to_binary(Reason, utf8)})
    end;
handle_function_('GetKeyringMeta', {}, _Context, _Opts) ->
    KeyringMeta = kds_keyring_manager:get_meta(),
    EncodedKeyringMeta = kds_keyring_meta:encode_keyring_meta(KeyringMeta),
    {ok, EncodedKeyringMeta}.

-spec encode_encrypted_shares([kds_keysharing:encrypted_master_key_share()]) -> [encrypted_masterkey_share()].
encode_encrypted_shares(EncryptedMasterKeyShares) ->
    lists:map(fun encode_encrypted_share/1, EncryptedMasterKeyShares).

-spec encode_encrypted_share(kds_keysharing:encrypted_master_key_share()) -> encrypted_masterkey_share().
encode_encrypted_share(#{
    id := Id,
    owner := Owner,
    encrypted_share := EncryptedShare
}) ->
    #cds_EncryptedMasterKeyShare{
        id = Id,
        owner = Owner,
        encrypted_share = EncryptedShare
    }.

-spec verify_signed_share(
    kds_shareholder:shareholder_id(),
    kds_keysharing:signed_masterkey_share(),
    atom()
) -> kds_keysharing:masterkey_share().
verify_signed_share(ShareholderId, SignedShare, OperationId) ->
    case kds_shareholder:get_public_key_by_id(ShareholderId, sig) of
        {ok, PublicKey} ->
            case kds_crypto:verify(PublicKey, SignedShare) of
                {ok, Share} ->
                    _ = logger:info(
                        "Shareholder ~w finished verification of operation ~w",
                        [ShareholderId, OperationId]
                    ),
                    Share;
                {error, failed_to_verify} ->
                    _ = logger:info(
                        "Shareholder ~w failed verification of operation ~w",
                        [ShareholderId, OperationId]
                    ),
                    raise(#cds_VerificationFailed{})
            end;
        {error, not_found} ->
            _ = logger:info(
                "Shareholder ~w failed verification of operation ~w",
                [ShareholderId, OperationId]
            ),
            raise(#cds_VerificationFailed{})
    end.

encode_state(#{
    status := Status,
    activities := #{
        initialization := #{
            phase := InitPhase,
            lifetime := InitLifetime,
            validation_shares := InitValShares
        },
        rotation := #{
            phase := RotatePhase,
            lifetime := RotateLifetime,
            confirmation_shares := RotateConShares
        },
        unlock := #{
            phase := UnlockPhase,
            lifetime := UnlockLifetime,
            confirmation_shares := UnlockConShares
        },
        rekeying := #{
            phase := RekeyPhase,
            lifetime := RekeyLifetime,
            confirmation_shares := RekeyConShares,
            validation_shares := RekeyValShares
        }
    }
}) ->
    #cds_KeyringState{
        status = Status,
        activities = #cds_ActivitiesState{
            initialization = #cds_InitializationState{
                phase = InitPhase,
                lifetime = InitLifetime,
                validation_shares = InitValShares
            },
            rotation = #cds_RotationState{
                phase = RotatePhase,
                lifetime = RotateLifetime,
                confirmation_shares = RotateConShares
            },
            unlock = #cds_UnlockState{
                phase = UnlockPhase,
                lifetime = UnlockLifetime,
                confirmation_shares = UnlockConShares
            },
            rekeying = #cds_RekeyingState{
                phase = RekeyPhase,
                lifetime = RekeyLifetime,
                confirmation_shares = RekeyConShares,
                validation_shares = RekeyValShares
            }
        }
    }.

decode_signed_share(#cds_SignedMasterKeyShare{
    id = ShareholderId,
    signed_share = Share
}) ->
    {ShareholderId, Share}.

-spec raise(_) -> no_return().
raise(Exception) ->
    kds_thrift_handler_utils:raise(Exception).
