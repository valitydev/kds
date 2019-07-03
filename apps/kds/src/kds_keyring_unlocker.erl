-module(kds_keyring_unlocker).

-behavior(gen_statem).

-include_lib("shamir/include/shamir.hrl").

-define(STATEM, ?MODULE).

%% API
-export([init/1, callback_mode/0]).

-export([start_link/0]).
-export([initialize/0]).
-export([confirm/3]).
-export([get_status/0]).
-export([cancel/0]).
-export([handle_event/4]).
-export_type([status/0]).
-export_type([state/0]).

-record(data, {
    shares = #{} :: #{kds_keysharing:share_id() => {shareholder_id(), masterkey_share()}},
    timer :: reference() | undefined
}).

-type data() :: #data{}.
-type seconds() :: non_neg_integer().
-type status() :: #{
    phase := state(),
    lifetime := seconds() | undefined,
    confirmation_shares := #{kds_keysharing:share_id() => shareholder_id()}
}.

-type state() :: uninitialized | validation.

-type shareholder_id() :: kds_shareholder:shareholder_id().
-type masterkey_share() :: kds_keysharing:masterkey_share().
-type masterkey_shares() :: kds_keysharing:masterkey_shares().
-type locked_keyring() :: kds_keyring:encrypted_keyring().
-type keyring() :: kds_keyring:keyring().
-type unlock_errors() ::
    wrong_masterkey | failed_to_recover.
-type invalid_activity() :: {error, {invalid_activity, {unlock, state()}}}.
-type unlock_resp() ::
    {ok, {done, keyring()}} |
    {ok, {more, pos_integer()}} |
    {error, {operation_aborted, unlock_errors()}}.

-spec callback_mode() -> handle_event_function.

callback_mode() -> handle_event_function.

-spec start_link() -> {ok, pid()}.

start_link() ->
    gen_statem:start_link({local, ?STATEM}, ?MODULE, [], []).

-spec initialize() -> ok | invalid_activity().

initialize() ->
    call(initialize).

-spec confirm(shareholder_id(), masterkey_share(), locked_keyring()) -> unlock_resp() | invalid_activity().

confirm(ShareholderId, Share, LockedKeyring) ->
    call({confirm, ShareholderId, Share, LockedKeyring}).

-spec cancel() -> ok.

cancel() ->
    call(cancel).

-spec get_status() -> status().

get_status() ->
    call(get_status).

call(Msg) ->
    gen_statem:call(?STATEM, Msg).

-spec init(_) -> {ok, state(), data()}.

init([]) ->
    {ok, uninitialized, #data{}}.

-spec handle_event(gen_statem:event_type(), term(), state(), data()) ->
    gen_statem:event_handler_result(state()).

%% Successful workflow events

handle_event({call, From}, initialize, uninitialized, _Data) ->
    TimerRef = erlang:start_timer(get_timeout(), self(), lifetime_expired),
    {next_state,
        validation,
        #data{timer = TimerRef},
        {reply, From, ok}};

handle_event({call, From}, {confirm, ShareholderId, Share, LockedKeyring}, validation,
    #data{shares = Shares, timer = TimerRef} = StateData) ->
    #share{threshold = Threshold, x = X} = kds_keysharing:decode_share(Share),
    case Shares#{X => {ShareholderId, Share}} of
        AllShares when map_size(AllShares) =:= Threshold ->
            _ = erlang:cancel_timer(TimerRef),
            ListShares = kds_keysharing:get_shares(AllShares),
            Result = unlock(LockedKeyring, ListShares),
            {next_state, uninitialized, #data{}, {reply, From, Result}};
        More ->
            {keep_state,
                StateData#data{shares = More},
                {reply, From, {ok, {more, Threshold - map_size(More)}}}}
    end;

%% Common events

handle_event({call, From}, get_state, State, _Data) ->
    {keep_state_and_data,
        {reply, From, State}
    };
handle_event({call, From}, get_status, State, #data{timer = TimerRef, shares = ValidationShares}) ->
    Lifetime = get_lifetime(TimerRef),
    ValidationSharesStripped = kds_keysharing:get_id_map(ValidationShares),
    Status = #{
        phase => State,
        lifetime => Lifetime,
        confirmation_shares => ValidationSharesStripped
    },
    {keep_state_and_data, {reply, From, Status}};
handle_event({call, From}, cancel, _State, #data{timer = TimerRef}) ->
    ok = cancel_timer(TimerRef),
    {next_state, uninitialized, #data{}, {reply, From, ok}};
handle_event(info, {timeout, _TimerRef, lifetime_expired}, _State, _Data) ->
    {next_state, uninitialized, #data{}, []};

%% InvalidActivity events

handle_event({call, From}, _Event, uninitialized, _Data) ->
    {keep_state_and_data,
        {reply, From, {error, {invalid_activity, {unlock, uninitialized}}}}
    };
handle_event({call, From}, _Event, validation, _Data) ->
    {keep_state_and_data,
        {reply, From, {error, {invalid_activity, {unlock, validation}}}}
    }.

-spec get_timeout() -> non_neg_integer().

get_timeout() ->
    application:get_env(kds, keyring_unlock_lifetime, 60000).

-spec get_lifetime(reference() | undefined) -> seconds() | undefined.

get_lifetime(TimerRef) ->
    case TimerRef of
        undefined ->
            undefined;
        TimerRef ->
            erlang:read_timer(TimerRef) div 1000
    end.

-spec unlock(locked_keyring(), masterkey_shares()) ->
    {ok, {done, keyring()}} | {error, {operation_aborted, unlock_errors()}}.

unlock(LockedKeyring, AllShares) ->
    case kds_keysharing:recover(AllShares) of
        {ok, MasterKey} ->
            case kds_keyring:decrypt(MasterKey, LockedKeyring) of
                {ok, UnlockedKeyring} ->
                    {ok, {done, UnlockedKeyring}};
                {error, decryption_failed} ->
                    {error, {operation_aborted, wrong_masterkey}}
            end;
        {error, Error} ->
            {error, {operation_aborted, Error}}
    end.

cancel_timer(undefined) ->
    ok;
cancel_timer(TimerRef) ->
    _ = erlang:cancel_timer(TimerRef),
    ok.
