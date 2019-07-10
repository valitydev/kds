-module(kds_keyring_rekeyer).

-behavior(gen_statem).

-include_lib("shamir/include/shamir.hrl").

%% API
-export([init/1, callback_mode/0]).
-export([start_link/0]).
-export([initialize/1]).
-export([confirm/3]).
-export([start_validation/1]).
-export([validate/3]).
-export([get_status/0]).
-export([cancel/0]).
-export([handle_event/4]).
-export_type([encrypted_master_key_shares/0]).
-export_type([status/0]).
-export_type([state/0]).

-define(STATEM, ?MODULE).

-record(data, {
    threshold,
    validation_keyring,
    shareholders,
    confirmation_shares = #{},
    validation_shares = #{},
    timer
}).

-type shareholder_id() :: kds_shareholder:shareholder_id().
-type masterkey_share() :: kds_keysharing:masterkey_share().
-type masterkey_shares() :: kds_keysharing:masterkey_shares_map().
-type masterkey_shares_list() :: kds_keysharing:masterkey_shares().
-type encrypted_master_key_shares() :: kds_keysharing:encrypted_master_key_shares().

-type data() :: #data{}.
-type seconds() :: non_neg_integer().
-type status() :: #{
    phase := state(),
    lifetime := seconds() | undefined,
    confirmation_shares := #{kds_keysharing:share_id() => shareholder_id()},
    validation_shares := #{kds_keysharing:share_id() => shareholder_id()}
}.

-type encrypted_keyring() :: kds_keyring:encrypted_keyring().
-type keyring() :: kds_keyring:keyring().

-type state() :: uninitialized | validation.

-type threshold() :: kds_keysharing:threshold().

-type validate_errors() :: {operation_aborted,
    non_matching_masterkey | failed_to_decrypt_keyring | failed_to_recover}.
-type confirm_errors() :: {operation_aborted,
    failed_to_recover | wrong_masterkey}.
-type initialize_errors() :: invalid_args.
-type invalid_activity_errors() :: {invalid_activity, state()}.

-spec callback_mode() -> handle_event_function.

callback_mode() -> handle_event_function.

-spec start_link() -> {ok, pid()}.

start_link() ->
    gen_statem:start_link({local, ?STATEM}, ?MODULE, [], []).

-spec initialize(threshold()) ->
    ok | {error, initialize_errors() | invalid_activity_errors()}.

initialize(Threshold) ->
    call({initialize, Threshold}).

-spec confirm(shareholder_id(), masterkey_share(), encrypted_keyring()) ->
    {ok, {more, pos_integer()}} | ok | {error, confirm_errors() | invalid_activity_errors()}.

confirm(ShareholderId, Share, EncryptedKeyring) ->
    call({confirm, ShareholderId, Share, EncryptedKeyring}).

-spec start_validation(keyring()) -> {ok, encrypted_master_key_shares()} | {error, invalid_activity_errors()}.

start_validation(Keyring) ->
    call({start_validatation, Keyring}).

-spec validate(shareholder_id(), masterkey_share(), keyring()) ->
    {ok, {more, pos_integer()}} |
    {ok, {done, encrypted_keyring()}} |
    {error, validate_errors() | invalid_activity_errors()}.

validate(ShareholderId, Share, Keyring) ->
    call({validate, ShareholderId, Share, Keyring}).

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

-spec handle_event(gen_statem:event_type(), term(), state(), data()) ->
    gen_statem:event_handler_result(state()).

%% Successful workflow events

handle_event({call, From}, {initialize, Threshold}, uninitialized, _Data) ->
    Shareholders = kds_shareholder:get_all(),
    ShareholdersLength = length(Shareholders),
    case (Threshold >= 1) and (ShareholdersLength >= 1) and (Threshold =< ShareholdersLength) of
        true ->
            TimerRef = erlang:start_timer(get_timeout(), self(), lifetime_expired),
            NewData = #data{
                threshold = Threshold,
                shareholders = Shareholders,
                timer = TimerRef},
            _ = logger:info("kds_keyring_rekeyer changed state to confirmation"),
            {next_state,
                confirmation,
                NewData,
                {reply, From, ok}};
        false ->
            {next_state,
                uninitialized,
                #data{},
                {reply, From, {error, invalid_args}}}
    end;
handle_event({call, From}, {confirm, ShareholderId, Share, EncryptedKeyring}, confirmation,
    #data{confirmation_shares = Shares, timer = TimerRef} = Data) ->
    #share{x = X, threshold = Threshold} = kds_keysharing:decode_share(Share),
    case Shares#{X => {ShareholderId, Share}} of
        AllShares when map_size(AllShares) =:= Threshold ->
            ListShares = kds_keysharing:get_shares(AllShares),
            case confirm_operation(EncryptedKeyring, ListShares) of
                ok ->
                    NewData = Data#data{confirmation_shares = AllShares},
                    _ = logger:info("kds_keyring_rekeyer changed state to postconfirmation"),
                    {next_state,
                        postconfirmation,
                        NewData,
                        {reply, From, ok}};
                {error, Error} ->
                    _Time = erlang:cancel_timer(TimerRef),
                    _ = logger:info("kds_keyring_rekeyer changed state to uninitialized"),
                    {next_state,
                        uninitialized,
                        #data{},
                        {reply, From, {error, Error}}}
            end;
        Shares1 ->
            NewData = Data#data{confirmation_shares = Shares1},
            {next_state,
                confirmation,
                NewData,
                {reply, From, {ok, {more, Threshold - maps:size(Shares1)}}}}
    end;
handle_event({call, From}, {start_validatation, Keyring}, postconfirmation,
    #data{shareholders = Shareholders, threshold = Threshold} = Data) ->
    MasterKey = kds_crypto:key(),
    EncryptedKeyring = kds_keyring:encrypt(MasterKey, Keyring),
    Shares = kds_keysharing:share(MasterKey, Threshold, length(Shareholders)),
    EncryptedShares = kds_keysharing:encrypt_shares_for_shareholders(Shares, Shareholders),
    NewData = Data#data{validation_keyring = EncryptedKeyring},
    _ = logger:info("kds_keyring_rekeyer changed state to validation"),
    {next_state,
        validation,
        NewData,
        {reply, From, {ok, EncryptedShares}}};
handle_event({call, From}, {validate, ShareholderId, Share, Keyring}, validation,
    #data{
        shareholders = Shareholders,
        threshold = Threshold,
        validation_shares = Shares,
        confirmation_shares = ConfirmationShares,
        validation_keyring = ValidationKeyring,
        timer = TimerRef} = Data) ->
    #share{x = X} = kds_keysharing:decode_share(Share),
    ShareholdersCount = length(Shareholders),
    case Shares#{X => {ShareholderId, Share}} of
        AllShares when map_size(AllShares) =:= ShareholdersCount ->
            _Time = erlang:cancel_timer(TimerRef),
            Result = validate_operation(Threshold, AllShares, ConfirmationShares, ValidationKeyring, Keyring),
            _ = logger:info("kds_keyring_rekeyer changed state to uninitialized"),
            {next_state,
                uninitialized,
                #data{
                    validation_shares = kds_keysharing:clear_shares(Shares),
                    confirmation_shares = kds_keysharing:clear_shares(ConfirmationShares)
                },
                {reply, From, Result}};
        Shares1 ->
            NewData = Data#data{validation_shares = Shares1},
            {next_state,
                validation,
                NewData,
                {reply, From, {ok, {more, ShareholdersCount - maps:size(Shares1)}}}}
    end;

%% Common events

handle_event({call, From}, get_state, State, _Data) ->
    {keep_state_and_data, [
        {reply, From, State}
    ]};
handle_event({call, From}, get_status, State,
    #data{timer = TimerRef, confirmation_shares = ConfirmationShares, validation_shares = ValidationShares}) ->
    Lifetime = get_lifetime(TimerRef),
    ConfirmationSharesStripped = kds_keysharing:get_id_map(ConfirmationShares),
    ValidationSharesStripped = kds_keysharing:get_id_map(ValidationShares),
    Status = #{
        phase => State,
        lifetime => Lifetime,
        confirmation_shares => ConfirmationSharesStripped,
        validation_shares => ValidationSharesStripped
    },
    {keep_state_and_data, {reply, From, Status}};
handle_event({call, From}, cancel, _State, #data{timer = TimerRef}) ->
    ok = cancel_timer(TimerRef),
    _ = logger:info("kds_keyring_rekeyer changed state to uninitialized"),
    {next_state, uninitialized, #data{}, {reply, From, ok}};
handle_event(info, {timeout, _TimerRef, lifetime_expired}, _State, _Data) ->
    _ = logger:info("kds_keyring_rekeyer changed state to uninitialized"),
    {next_state, uninitialized, #data{}, []};

%% InvalidActivity events

handle_event({call, From}, _Event, uninitialized, _Data) ->
    {keep_state_and_data, [
        {reply, From, {error, {invalid_activity, {rekeying, uninitialized}}}}
    ]};
handle_event({call, From}, _Event, confirmation, _Data) ->
    {keep_state_and_data, [
        {reply, From, {error, {invalid_activity, {rekeying, confirmation}}}}
    ]};
handle_event({call, From}, _Event, postconfirmation, _Data) ->
    {keep_state_and_data, [
        {reply, From, {error, {invalid_activity, {rekeying, postconfirmation}}}}
    ]};
handle_event({call, From}, _Event, validation, _Data) ->
    {keep_state_and_data, [
        {reply, From, {error, {invalid_activity, {rekeying, validation}}}}
    ]}.

-spec get_timeout() -> non_neg_integer().

get_timeout() ->
    genlib_app:env(kds, keyring_rekeying_lifetime, 3 * 60 * 1000).

-spec get_lifetime(reference() | undefined) -> seconds() | undefined.

get_lifetime(TimerRef) ->
    case TimerRef of
        undefined ->
            undefined;
        TimerRef ->
            erlang:read_timer(TimerRef) div 1000
    end.

-spec confirm_operation(encrypted_keyring(), masterkey_shares_list()) -> ok | {error, confirm_errors()}.

confirm_operation(EncryptedOldKeyring, AllShares) ->
    case kds_keysharing:recover(AllShares) of
        {ok, MasterKey} ->
            case kds_keyring:validate_masterkey(MasterKey, EncryptedOldKeyring) of
                {ok, _Keyring} ->
                    ok;
                {error, wrong_masterkey} ->
                    {error, {operation_aborted, wrong_masterkey}}
            end;
        {error, failed_to_recover} ->
            {error, {operation_aborted, failed_to_recover}}
    end.

-spec validate_operation(threshold(), masterkey_shares(), masterkey_shares(), encrypted_keyring(), keyring()) ->
    {ok, {done, encrypted_keyring()}} | {error, validate_errors()}.

validate_operation(Threshold, ValidationShares, ConfirmationShares, ValidationKeyring, Keyring) ->
    ValidationListShares = kds_keysharing:get_shares(ValidationShares),
    case kds_keysharing:validate_shares(Threshold, ValidationListShares) of
        {ok, MasterKey} ->
            case kds_keyring:decrypt(MasterKey, ValidationKeyring) of
                {ok, _DecryptedKeyring} ->
                    EncryptedKeyring = kds_keyring:encrypt(MasterKey, Keyring),
                    ValidationShareholdersIds = kds_keysharing:get_shareholder_ids(ValidationShares),
                    ConfirmationShareholdersIds = kds_keysharing:get_shareholder_ids(ConfirmationShares),
                    _ = logger:info("Rekey finished with confrimation shares from ~p~nand validation shares from ~p",
                        [ValidationShareholdersIds, ConfirmationShareholdersIds]),
                    {ok, {done, EncryptedKeyring}};
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
