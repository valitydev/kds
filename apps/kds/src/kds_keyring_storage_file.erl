-module(kds_keyring_storage_file).
-behaviour(kds_keyring_storage).
-behaviour(gen_server).

-export([child_spec/1]).
-export([start_link/1]).
-export([create/1]).
-export([read/0]).
-export([update/1]).
-export([delete/0]).
-export([init/1, handle_call/3, handle_cast/2]).

-define(SERVER, ?MODULE).
-define(DEFAULT_KEYRING_PATH, "/var/lib/kds/keyring").

-record(state, {
    keyring_path :: string()
}).
-type state() :: #state{}.

-spec child_spec(map()) -> {ok, supervisor:child_spec()}.
child_spec(StorageOpts) ->
    KeyringPath = maps:get(keyring_path, StorageOpts, ?DEFAULT_KEYRING_PATH),
    {ok, #{
        id => ?SERVER,
        start => {?MODULE, start_link, [KeyringPath]}
    }}.

-spec start_link(string()) -> {ok, pid()}.
start_link(KeyringPath) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, KeyringPath, []).

-spec create(binary()) -> ok | {error, already_exists}.
create(Keyring) ->
    gen_server:call(?SERVER, {create, Keyring}).

-spec read() -> {ok, binary()} | {error, not_found}.
read() ->
    gen_server:call(?SERVER, read).

-spec update(binary()) -> ok.
update(Keyring) ->
    gen_server:call(?SERVER, {update, Keyring}).

-spec delete() -> ok.
delete() ->
    gen_server:call(?SERVER, delete).

-spec init(string()) -> {ok, state()}.
init(KeyringPath) ->
    {ok, #state{keyring_path = KeyringPath}}.

-spec handle_call(term(), term(), state()) -> {reply, term(), state()}.
handle_call({create, Keyring}, _From, #state{keyring_path = KeyringPath} = State) ->
    Reply = case filelib:is_regular(KeyringPath) of
        false ->
            ok = filelib:ensure_dir(KeyringPath),
            ok = atomic_write(KeyringPath, Keyring);
        true ->
            {error, already_exists}
    end,
    {reply, Reply, State};
handle_call(read, _From, #state{keyring_path = KeyringPath} = State) ->
    Reply = case file:read_file(KeyringPath) of
        {ok, Data} ->
            {ok, Data};
        {error, enoent} ->
            {error, not_found}
    end,
    {reply, Reply, State};
handle_call({update, Keyring}, _From, #state{keyring_path = KeyringPath} = State) ->
    ok = filelib:ensure_dir(KeyringPath),
    ok = atomic_write(KeyringPath, Keyring),
    {reply, ok, State};
handle_call(delete, _From, #state{keyring_path = KeyringPath} = State) ->
    _ = case file:delete(KeyringPath) of
        ok ->
            ok;
        {error, enoent} ->
            ok
    end,
    {reply, ok, State}.

-spec handle_cast(term(), state()) -> {noreply, state()}.
handle_cast(_Request, State) ->
    {noreply, State}.

atomic_write(Path, Keyring) ->
    TmpPath = tmp_keyring_path(Path),
    ok = file:write_file(TmpPath, Keyring),
    file:rename(TmpPath, Path).

tmp_keyring_path(Path) ->
    genlib:to_list(Path) ++ ".tmp".
