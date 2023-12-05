%% @doc Wrapper for all external backend calls.
%%
%% All backend behaviours must use only ok or {ok, term()} as response and
%% {error, term()} tuple for errors that are expected and which will be propagated to
%% corresponding thrift exception. All exceptions will be caught and logged
%% here and not propagated to interface handler
%%
-module(kds_backend).

-export([call/3]).

-spec call(atom(), atom(), list()) -> ok | term().
call(Key, Method, Args) ->
    {ok, Module} = application:get_env(kds, Key),
    try erlang:apply(Module, Method, Args) of
        ok ->
            ok;
        {ok, Return} ->
            Return;
        {error, Error} ->
            throw(Error)
    catch
        Class:Reason:Stacktrace ->
            _ = logger:error(
                "~p (~p) ~p failed~nClass: ~p~nReason: ~p",
                [Key, Module, Method, Class, Reason],
                #{stacktrace => genlib_format:format_stacktrace(Stacktrace)}
            ),
            handle_error(Class, Reason)
    end.

-spec handle_error(atom(), _) -> no_return().
handle_error(error, timeout) ->
    woody_error:raise(system, {internal, result_unknown, <<"timeout">>});
handle_error(Class, Reason) ->
    exit({backend_error, {Class, Reason}}).
