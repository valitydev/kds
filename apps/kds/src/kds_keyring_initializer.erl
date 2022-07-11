-module(kds_keyring_initializer).

-behaviour(gen_statem).

-include_lib("shamir/include/shamir.hrl").

%% API
-export([init/1, callback_mode/0]).
-export([start_link/0]).
-export([initialize/1]).
-export([validate/2]).
-export([get_status/0]).
-export([cancel/0]).
-export([handle_event/4]).

-export_type([encrypted_master_key_shares/0]).
-export_type([status/0]).
-export_type([state/0]).

-define(STATEM, ?MODULE).

-record(data, {
    num :: pos_integer() | undefined,
    threshold :: pos_integer() | undefined,
    keyring :: encrypted_keyring() | undefined,
    shares = #{} :: masterkey_shares_map(),
    timer :: reference() | undefined
}).

-type shareholder_id() :: kds_shareholder:shareholder_id().

-type masterkey_share() :: kds_keysharing:masterkey_share().
-type masterkey_shares_map() :: kds_keysharing:masterkey_shares_map().

-type encrypted_master_key_shares() :: kds_keysharing:encrypted_master_key_shares().

-type data() :: #data{}.
-type seconds() :: non_neg_integer().
-type status() :: #{
    phase := state(),
    lifetime := seconds() | undefined,
    validation_shares := #{kds_keysharing:share_id() => shareholder_id()}
}.

-type encrypted_keyring() :: kds_keyring:encrypted_keyring().
-type decrypted_keyring() :: kds_keyring:keyring().

-type state() :: uninitialized | validation.

-type threshold() :: kds_keysharing:threshold().

-type validate_errors() :: {operation_aborted, non_matching_masterkey | failed_to_decrypt_keyring | failed_to_recover}.
-type initialize_errors() :: invalid_args.
-type invalid_activity() :: {error, {invalid_activity, {initialization, state()}}}.

-spec callback_mode() -> handle_event_function.
callback_mode() -> handle_event_function.

-spec start_link() -> {ok, pid()}.
start_link() ->
    gen_statem:start_link({local, ?STATEM}, ?MODULE, [], []).

-spec initialize(threshold()) ->
    {ok, encrypted_master_key_shares()} | {error, initialize_errors()} | invalid_activity().
initialize(Threshold) ->
    call({initialize, Threshold}).

-spec validate(shareholder_id(), masterkey_share()) ->
    {ok, {more, pos_integer()}}
    | {ok, {done, {encrypted_keyring(), decrypted_keyring()}}}
    | {error, validate_errors()}
    | invalid_activity().
validate(ShareholderId, Share) ->
    call({validate, ShareholderId, Share}).

-spec cancel() -> ok.
cancel() ->
    call(cancel).

-spec get_status() -> status().
get_status() ->
    call(get_status).

call(Message) ->
    gen_statem:call(?STATEM, Message).

-spec init(term()) -> {ok, state(), data()}.
init([]) ->
    {ok, uninitialized, #data{}}.

-spec handle_event(gen_statem:event_type(), term(), state(), data()) -> gen_statem:event_handler_result(state()).
%% Successful workflow events

handle_event({call, From}, {initialize, Threshold}, uninitialized, _Data) ->
    Shareholders = kds_shareholder:get_all(),
    ShareholdersLength = length(Shareholders),
    case (Threshold >= 1) and (ShareholdersLength >= 1) and (Threshold =< ShareholdersLength) of
        true ->
            MasterKey = kds_crypto:key(),
            Keyring = kds_keyring:new(),
            EncryptedKeyring = kds_keyring:encrypt(MasterKey, Keyring),
            Shares = kds_keysharing:share(MasterKey, Threshold, ShareholdersLength),
            EncryptedShares = kds_keysharing:encrypt_shares_for_shareholders(Shares, Shareholders),
            TimerRef = erlang:start_timer(get_timeout(), self(), lifetime_expired),
            NewData = #data{
                num = length(EncryptedShares),
                threshold = Threshold,
                keyring = EncryptedKeyring,
                timer = TimerRef
            },
            _ = logger:info("kds_keyring_initializer changed state to validation"),
            {next_state, validation, NewData, {reply, From, {ok, EncryptedShares}}};
        false ->
            {next_state, uninitialized, #data{}, {reply, From, {error, invalid_args}}}
    end;
handle_event(
    {call, From},
    {validate, ShareholderId, Share},
    validation,
    #data{num = Num, threshold = Threshold, shares = Shares, keyring = Keyring, timer = TimerRef} = Data
) ->
    #share{x = X} = kds_keysharing:decode_share(Share),
    case Shares#{X => {ShareholderId, Share}} of
        AllShares when map_size(AllShares) =:= Num ->
            _ = erlang:cancel_timer(TimerRef),
            Result = validate(Threshold, AllShares, Keyring),
            _ = logger:info("kds_keyring_initializer changed state to uninitialized"),
            {next_state, uninitialized, #data{shares = kds_keysharing:clear_shares(Shares)}, {reply, From, Result}};
        Shares1 ->
            NewData = Data#data{shares = Shares1},
            {next_state, validation, NewData, {reply, From, {ok, {more, Num - maps:size(Shares1)}}}}
    end;
%% Common events

handle_event({call, From}, get_state, State, _Data) ->
    {keep_state_and_data, [
        {reply, From, State}
    ]};
handle_event({call, From}, get_status, State, #data{timer = TimerRef, shares = ValidationShares}) ->
    Lifetime = get_lifetime(TimerRef),
    ValidationSharesStripped = kds_keysharing:get_id_map(ValidationShares),
    Status = #{
        phase => State,
        lifetime => Lifetime,
        validation_shares => ValidationSharesStripped
    },
    {keep_state_and_data, {reply, From, Status}};
handle_event({call, From}, cancel, _State, #data{timer = TimerRef}) ->
    ok = cancel_timer(TimerRef),
    _ = logger:info("kds_keyring_initializer changed state to uninitialized"),
    {next_state, uninitialized, #data{}, {reply, From, ok}};
handle_event(info, {timeout, _TimerRef, lifetime_expired}, _State, _Data) ->
    _ = logger:info("kds_keyring_initializer changed state to uninitialized"),
    {next_state, uninitialized, #data{}, []};
%% InvalidActivity events

handle_event({call, From}, _Event, uninitialized, _Data) ->
    {keep_state_and_data, [
        {reply, From, {error, {invalid_activity, {initialization, uninitialized}}}}
    ]};
handle_event({call, From}, _Event, validation, _Data) ->
    {keep_state_and_data, [
        {reply, From, {error, {invalid_activity, {initialization, validation}}}}
    ]}.

-spec get_timeout() -> non_neg_integer().
get_timeout() ->
    genlib_app:env(kds, keyring_initialize_lifetime, 3 * 60 * 1000).

-spec get_lifetime(reference() | undefined) -> seconds() | undefined.
get_lifetime(TimerRef) ->
    case TimerRef of
        undefined ->
            undefined;
        TimerRef ->
            erlang:read_timer(TimerRef) div 1000
    end.

-spec validate(threshold(), masterkey_shares_map(), encrypted_keyring()) ->
    {ok, {done, {encrypted_keyring(), decrypted_keyring()}}} | {error, validate_errors()}.
validate(Threshold, Shares, EncryptedKeyring) ->
    ListShares = kds_keysharing:get_shares(Shares),
    case kds_keysharing:validate_shares(Threshold, ListShares) of
        {ok, MasterKey} ->
            case kds_keyring:decrypt(MasterKey, EncryptedKeyring) of
                {ok, DecryptedKeyring} ->
                    InitializersIds = kds_keysharing:get_shareholder_ids(Shares),
                    _ = logger:info("Initialization finished with shares from ~p", [InitializersIds]),
                    {ok, {done, {EncryptedKeyring, DecryptedKeyring}}};
                {error, decryption_failed} ->
                    {error, {operation_aborted, failed_to_decrypt_keyring}}
            end;
        {error, Error} ->
            {error, {operation_aborted, Error}}
    end.

cancel_timer(undefined) ->
    ok;
cancel_timer(TimerRef) ->
    _ = erlang:cancel_timer(TimerRef),
    ok.
