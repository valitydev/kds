-module(kds_woody_event_handler).

-behaviour(woody_event_handler).

-include_lib("cds_proto/include/cds_proto_keyring_thrift.hrl").
-include_lib("woody/src/woody_defs.hrl").

%% woody_event_handler behaviour callbacks
-export([handle_event/4]).

%%
%% woody_event_handler behaviour callbacks
%%
-spec handle_event(Event, RpcID, Meta, Opts) -> ok when
    Event :: woody_event_handler:event(),
    RpcID :: woody:rpc_id() | undefined,
    Meta :: woody_event_handler:event_meta(),
    Opts :: woody:options().
handle_event(Event, RpcID, RawMeta, Opts) ->
    FilteredMeta = filter_meta(RawMeta),
    scoper_woody_event_handler:handle_event(Event, RpcID, FilteredMeta, Opts).

%% Internals

filter_meta(RawMeta0) ->
    maps:map(fun do_filter_meta/2, RawMeta0).

do_filter_meta(result, Result) ->
    filter(Result);
do_filter_meta(reason, Error) ->
    filter(Error);
do_filter_meta(args, Args) ->
    filter(Args);
do_filter_meta(_Key, Value) ->
    Value.

filter(#cds_EncryptedMasterKeyShare{} = EncryptedMasterKeyShare) ->
    EncryptedMasterKeyShare#cds_EncryptedMasterKeyShare{encrypted_share = <<"***">>};
filter(#cds_SignedMasterKeyShare{} = SignedShare) ->
    SignedShare#cds_SignedMasterKeyShare{signed_share = <<"***">>};
filter(#cds_Keyring{keys = Keys} = Keyring) ->
    Keyring#cds_Keyring{keys = filter(Keys)};
filter(#cds_Key{} = Key) ->
    Key#cds_Key{data = <<"***">>};
filter({success, #cds_Success{}} = V) ->
    V;
filter({more_keys_needed, D} = V) when is_integer(D) ->
    V;
filter(#cds_KeyringState{} = V) ->
    V;
filter(#cds_KeyringMeta{} = V) ->
    V;
filter(#cds_KeyringMetaDiff{} = V) ->
    V;
filter(#cds_InvalidStatus{} = V) ->
    V;
filter(#cds_InvalidActivity{} = V) ->
    V;
filter(#cds_InvalidKeyringMeta{} = V) ->
    V;
filter(#cds_InvalidArguments{} = V) ->
    V;
filter(#cds_VerificationFailed{} = V) ->
    V;
filter(#cds_OperationAborted{} = V) ->
    V;
%% woody errors
filter({internal, Error, Details} = V) when is_atom(Error) and is_binary(Details) ->
    V;
filter({external, Error, Details} = V) when is_atom(Error) and is_binary(Details) ->
    V;
%% Known woody error reasons
filter(<<"Deadline reached">> = V) ->
    V;
filter(<<"partial response">> = V) ->
    V;
filter(<<"thrift protocol read failed">> = V) ->
    V;
%% common
filter(V) when is_atom(V) ->
    V;
filter(V) when is_number(V) ->
    V;
filter(L) when is_list(L) ->
    [filter(E) || E <- L];
filter(T) when is_tuple(T) ->
    list_to_tuple(filter(tuple_to_list(T)));
filter(M) when is_map(M) ->
    genlib_map:truemap(fun(K, V) -> {filter(K), filter(V)} end, M);
filter(B) when is_bitstring(B) ->
    <<"***">>;
filter(P) when is_pid(P) ->
    P;
filter(P) when is_port(P) ->
    P;
filter(F) when is_function(F) ->
    F;
filter(R) when is_reference(R) ->
    R;
%% fallback
filter(_V) ->
    <<"*filtered*">>.
