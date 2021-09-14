-module(kds_keyring_storage_thrift_handler).

-behaviour(woody_server_thrift_handler).

-include_lib("cds_proto/include/cds_proto_keyring_thrift.hrl").

%% woody_server_thrift_handler callbacks
-export([handle_function/4]).

%%
%% woody_server_thrift_handler callbacks
%%

-spec handle_function(woody:func(), woody:args(), woody_context:ctx(), woody:options()) ->
    {ok, woody:result()} | no_return().
handle_function(OperationID, Args, Context, Opts) ->
    scoper:scope(
        keyring_storage,
        kds_thrift_handler_utils:filter_fun_exceptions(
            fun() ->
                handle_function_(OperationID, Args, Context, Opts)
            end
        )
    ).

handle_function_('GetKeyring', {}, _Context, _Opts) ->
    try kds_keyring_manager:get_keyring() of
        Keyring ->
            {ok, encode_keyring(Keyring)}
    catch
        {invalid_status, Status} ->
            raise(#cds_InvalidStatus{status = Status})
    end.

encode_keyring(#{
    data := #{
        keys := Keys
    },
    meta := #{
        current_key_id := CurrentKeyId,
        version := Version,
        keys := KeysMeta
    }
}) ->
    #cds_Keyring{
        version = Version,
        current_key_id = CurrentKeyId,
        keys = encode_keys(Keys, KeysMeta)
    }.

encode_keys(Keys, KeysMeta) ->
    maps:fold(
        fun(K, V, Acc) ->
            #{
                retired := Retired,
                security_parameters := SecurityParameters
            } = maps:get(K, KeysMeta),
            Acc#{
                K => #cds_Key{
                    data = V,
                    meta = #cds_KeyMeta{
                        retired = Retired,
                        security_parameters = kds_keyring_meta:encode_security_parameters(SecurityParameters)
                    }
                }
            }
        end,
        #{},
        Keys
    ).

-spec raise(_) -> no_return().
raise(Exception) ->
    kds_thrift_handler_utils:raise(Exception).
