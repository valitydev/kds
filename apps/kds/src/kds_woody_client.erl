-module(kds_woody_client).

-export([call/4]).
-export([call/5]).

%%
%% Types
%%

-type result() :: woody:result()
    | {exception, woody_error:business_error()}
    | no_return().

-export_type([result/0]).

%%
%% API
%%

-spec call(atom(), atom(), list(), woody:url()) -> result().
call(ServiceCode, Function, Args, RootUrl) ->
    call(ServiceCode, Function, Args, RootUrl, #{}).

-spec call(atom(), atom(), list(), woody:url(), woody_client:options() | map()) -> result().
call(ServiceCode, Function, Args, RootUrl, ExtraOpts) ->
    Request = {kds_thrift_services:service(ServiceCode), Function, Args},
    Path = genlib:to_binary(kds_thrift_services:path(ServiceCode)),
    CallOpts = maps:merge(ExtraOpts, #{
        url => <<RootUrl/binary, Path/binary>>,
        event_handler => scoper_woody_event_handler
    }),
    case woody_client:call(Request, CallOpts) of
        {ok, Result} ->
            Result;
        {exception, Exception} ->
            throw(Exception)
    end.
