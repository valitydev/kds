-module(kds_ct_stash).

-export([start/0]).
-export([stop/1]).
-export([put/3]).
-export([get/2]).

-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2
]).

-spec start() -> pid().
start() ->
    {ok, Pid} = gen_server:start(?MODULE, [], []),
    Pid.

-spec stop(pid()) -> ok.
stop(Pid) ->
    proc_lib:stop(Pid, shutdown, 5000).

-spec put(pid(), term(), term()) -> ok.
put(Pid, Key, Value) ->
    gen_server:call(Pid, {put, Key, Value}, 5000).

-spec get(pid(), term()) -> term().
get(Pid, Key) ->
    gen_server:call(Pid, {get, Key}, 5000).

%%

-spec init(term()) -> {ok, map()}.
init(_) ->
    {ok, #{}}.

-spec handle_call(term(), pid(), map()) -> {reply, atom(), map()}.
handle_call({put, Key, Value}, _From, State) ->
    {reply, ok, State#{Key => Value}};
handle_call({get, Key}, _From, State) ->
    Value = maps:get(Key, State, undefined),
    {reply, Value, State}.

-spec handle_cast(term(), map()) -> {noreply, map()}.
handle_cast(_Msg, State) ->
    {noreply, State}.

-spec handle_info(term(), map()) -> {noreply, map()}.
handle_info(_Info, State) ->
    {noreply, State}.
