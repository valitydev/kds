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
-define(FORMAT_VERSION, 1).

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

-spec create(kds_keyring:encrypted_keyring()) -> ok | {error, already_exists}.
create(Keyring) ->
    gen_server:call(?SERVER, {create, Keyring}).

-spec read() -> {ok, kds_keyring:encrypted_keyring()} | {error, not_found}.
read() ->
    gen_server:call(?SERVER, read).

-spec update(kds_keyring:encrypted_keyring()) -> ok.
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
            KeyringWithFormat = Keyring#{
                format_version => ?FORMAT_VERSION
            },
            ok = filelib:ensure_dir(KeyringPath),
            ok = atomic_write(KeyringPath, jsx:encode(KeyringWithFormat));
        true ->
            {error, already_exists}
    end,
    {reply, Reply, State};
handle_call(read, _From, #state{keyring_path = KeyringPath} = State) ->
    Reply = case file:read_file(KeyringPath) of
        {ok, Data} ->
            case jsx:is_json(Data) of
                true ->
                    DecodedData = decode_encrypted_keyring(
                        jsx:decode(Data, [return_maps, {labels, binary}])),
                    {ok, #{data => maps:get(data, DecodedData), meta => maps:get(meta, DecodedData)}};
                false ->
                    {ok, #{data => Data, meta => undefined}}
            end;
        {error, enoent} ->
            {error, not_found}
    end,
    {reply, Reply, State};
handle_call({update, Keyring}, _From, #state{keyring_path = KeyringPath} = State) ->
    KeyringWithFormat = Keyring#{
        format_version => ?FORMAT_VERSION
    },
    ok = filelib:ensure_dir(KeyringPath),
    ok = atomic_write(KeyringPath, jsx:encode(KeyringWithFormat)),
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
    ok = file:write_file(TmpPath, Keyring, [sync]),
    file:rename(TmpPath, Path).

tmp_keyring_path(Path) ->
    genlib:to_list(Path) ++ ".tmp".

-spec decode_encrypted_keyring(map()) -> kds_keyring:encrypted_keyring().
decode_encrypted_keyring(#{
    <<"format_version">> := 1,
    <<"data">> := KeyringData,
    <<"meta">> := #{
        <<"current_key_id">> := CurrentKeyId,
        <<"version">> := Version,
        <<"keys">> := KeysMeta
    }
})->
    #{
        data => KeyringData,
        meta => #{
            current_key_id => CurrentKeyId,
            version => Version,
            keys => decode_number_key_map(KeysMeta)
        }
    }.

decode_number_key_map(Map) ->
    maps:fold(
        fun (K,
            #{
                <<"retired">> := Retired,
                <<"security_parameters">> := #{
                    <<"deduplication_hash_opts">> := #{
                        <<"n">> := ScryptN,
                        <<"r">> := ScryptR,
                        <<"p">> := ScryptP
                    }
                }
            },
            Acc) ->
            Acc#{
                binary_to_integer(K) => #{
                    retired => Retired,
                    security_parameters => #{
                        deduplication_hash_opts => #{
                            n => ScryptN,
                            r => ScryptR,
                            p => ScryptP
                        }
                    }
                }
            }
        end,
        #{},
        Map).
