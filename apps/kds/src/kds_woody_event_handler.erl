-module(kds_woody_event_handler).

-behaviour(woody_event_handler).

-include_lib("cds_proto/include/cds_proto_keyring_thrift.hrl").
-include_lib("woody/src/woody_defs.hrl").

%% woody_event_handler behaviour callbacks
-export([handle_event/4]).

%%
%% woody_event_handler behaviour callbacks
%%
-spec handle_event(Event, RpcId, Meta, Opts) ->
    ok
    when
    Event :: woody_event_handler:event(),
    RpcId :: woody:rpc_id() | undefined,
    Meta  :: woody_event_handler:event_meta(),
    Opts  :: woody:options().

handle_event(?EV_INTERNAL_ERROR, RpcID, RawMeta, Opts) ->
    RawMetaWithoutReason = RawMeta#{reason => <<"***">>},
    scoper_woody_event_handler:handle_event(?EV_INTERNAL_ERROR, RpcID, RawMetaWithoutReason, Opts);
handle_event(Event, RpcID, RawMeta, Opts) ->
    FilteredMeta = filter_meta(RawMeta),
    scoper_woody_event_handler:handle_event(Event, RpcID, FilteredMeta, Opts).

filter_meta(RawMeta) ->
    case RawMeta of
        #{result := Result} ->
            RawMeta#{result => filter_result(Result)};
        #{args := Args} ->
            RawMeta#{args => filter_args(Args)};
        _ ->
            RawMeta
    end.

filter_result({ok, Result}) -> {ok, filter(Result)};
filter_result({system, SystemError}) -> {system, filter(SystemError)};
filter_result({exception, Exception}) -> {exception, filter(Exception)};
filter_result(Result) -> filter(Result).

filter_args(Args) -> filter(Args).

filter(L) when is_list(L) -> [filter(E) || E <- L];
filter(M) when is_map(M) -> maps:map(fun (_K, V) -> filter(V) end, M);

filter({internal, Error, Details} = V) when is_atom(Error) and is_binary(Details) -> V;
filter({external, Error, Details} = V) when is_atom(Error) and is_binary(Details) -> V;

filter(#cds_EncryptedMasterKeyShare{} = EncryptedMasterKeyShare) ->
    EncryptedMasterKeyShare#cds_EncryptedMasterKeyShare{encrypted_share = <<"***">>};
filter(#cds_SignedMasterKeyShare{} = SignedShare) ->
    SignedShare#cds_SignedMasterKeyShare{signed_share = <<"***">>};
filter(#cds_Keyring{keys = Keys} = Keyring) ->
    Keyring#cds_Keyring{keys = filter(Keys)};
filter(#cds_Key{} = Key) ->
    Key#cds_Key{data = <<"***">>};

filter(V) when is_integer(V) -> V;
filter(ok) -> ok;
filter({success, #cds_Success{}} = V) -> V;
filter({more_keys_needed, D} = V) when is_integer(D) -> V;
filter(#cds_KeyringState{} = V) -> V;
filter(#cds_KeyringMeta{} = V) -> V;
filter(#cds_KeyringMetaDiff{} = V) -> V;

filter(#cds_InvalidStatus{} = V) -> V;
filter(#cds_InvalidActivity{} = V) -> V;
filter(#cds_InvalidKeyringMeta{} = V) -> V;
filter(#cds_InvalidArguments{} = V) -> V;
filter(#cds_VerificationFailed{} = V) -> V;
filter(#cds_OperationAborted{} = V) -> V.
