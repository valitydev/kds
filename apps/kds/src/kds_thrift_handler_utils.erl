-module(kds_thrift_handler_utils).

-export([filter_fun_exceptions/1]).
-export([raise/1]).

%%
%% API
%%

-spec filter_fun_exceptions(fun()) -> fun().
filter_fun_exceptions(Fun) ->
    fun() ->
        try
            Fun()
        catch
            throw:Exception ->
                throw(Exception);
            error:{woody_error, _} = WoodyError:Stacktrace ->
                erlang:raise(error, WoodyError, Stacktrace);
            Class:Exception:Stacktrace ->
                erlang:raise(Class, filter_error_reason(Exception), Stacktrace)
        end
    end.

-spec raise(_) -> no_return().
raise(Exception) ->
    woody_error:raise(business, Exception).

%%
%% Internals
%%

% Known safe errors
filter_error_reason({hash_collision_detected, _Hash} = Reason) ->
    Reason;
% Generic safe errors
filter_error_reason(Reason) when is_tuple(Reason) ->
    erlang:list_to_tuple([filter_error_reason(R) || R <- erlang:tuple_to_list(Reason)]);
filter_error_reason(Reason) when is_list(Reason) ->
    [filter_error_reason(R) || R <- Reason];
filter_error_reason(Reason) when is_map(Reason) ->
    maps:map(
        fun(_Key, Value) ->
            filter_error_reason(Value)
        end,
        Reason
    );
filter_error_reason(Reason) when
    is_atom(Reason) orelse
    is_number(Reason) orelse
    is_reference(Reason) orelse
    is_pid(Reason)
->
    Reason;
% Other
filter_error_reason(_Reason) ->
    '***'.
