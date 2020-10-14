-module(kds_keyring_manager).

-behaviour(gen_statem).

-include_lib("shamir/include/shamir.hrl").

%% API.
-export([start_link/0]).
-export([get_keyring/0]).
-export([start_unlock/0]).
-export([confirm_unlock/2]).
-export([cancel_unlock/0]).
-export([lock/0]).
-export([start_rotate/0]).
-export([confirm_rotate/2]).
-export([cancel_rotate/0]).
-export([initialize/1]).
-export([validate_init/2]).
-export([cancel_init/0]).
-export([start_rekey/1]).
-export([confirm_rekey/2]).
-export([start_validate_rekey/0]).
-export([validate_rekey/2]).
-export([cancel_rekey/0]).
-export([get_status/0]).
-export([update_meta/1]).
-export([get_meta/0]).

%% gen_statem.
-export([init/1]).
-export([callback_mode/0]).
-export([handle_event/4]).
-export([terminate/3]).
-export([code_change/4]).

-export_type([status/0]).
-export_type([state/0]).

-define(STATEM, ?MODULE).

-record(data, {
    keyring :: #{
        data := undefined | kds_keyring:keyring_data(),
        meta := undefined | kds_keyring_meta:keyring_meta()
    }
}).

-type data() :: #data{}.
-type state() :: locked | unlocked | not_initialized.
-type status() :: #{
    status := state(),
    activities := #{
        initialization := kds_keyring_initializer:status(),
        rotation := kds_keyring_rotator:status(),
        unlock := kds_keyring_unlocker:status(),
        rekeying := kds_keyring_rekeyer:status()
    }
}.

%% API.

-spec callback_mode() -> handle_event_function.
callback_mode() -> handle_event_function.

-spec start_link() -> {ok, pid()}.
start_link() ->
    gen_statem:start_link({local, ?STATEM}, ?MODULE, [], []).

-spec get_keyring() -> kds_keyring:keyring().
get_keyring() ->
    call(get_keyring).

-spec start_unlock() -> ok.
start_unlock() ->
    call(start_unlock).

-spec confirm_unlock(kds_shareholder:shareholder_id(), kds_keysharing:masterkey_share()) -> {more, pos_integer()} | ok.
confirm_unlock(ShareholderId, Share) ->
    call({confirm_unlock, ShareholderId, Share}).

-spec cancel_unlock() -> ok.
cancel_unlock() ->
    call(cancel_unlock).

-spec lock() -> ok.
lock() ->
    call(lock).

-spec start_rotate() -> ok.
start_rotate() ->
    call(start_rotate).

-spec confirm_rotate(kds_shareholder:shareholder_id(), kds_keysharing:masterkey_share()) -> {more, pos_integer()} | ok.
confirm_rotate(ShareholderId, Share) ->
    call({confirm_rotate, ShareholderId, Share}).

-spec cancel_rotate() -> ok.
cancel_rotate() ->
    call(cancel_rotate).

-spec initialize(integer()) -> kds_keyring_initializer:encrypted_master_key_shares().
initialize(Threshold) ->
    call({initialize, Threshold}).

-spec validate_init(kds_shareholder:shareholder_id(), kds_keysharing:masterkey_share()) -> {more, pos_integer()} | ok.
validate_init(ShareholderId, Share) ->
    call({validate_init, ShareholderId, Share}).

-spec cancel_init() -> ok.
cancel_init() ->
    call(cancel_init).

-spec start_rekey(integer()) -> ok.
start_rekey(Threshold) ->
    call({start_rekey, Threshold}).

-spec confirm_rekey(kds_shareholder:shareholder_id(), kds_keysharing:masterkey_share()) -> {more, pos_integer()} | ok.
confirm_rekey(ShareholderId, Share) ->
    call({confirm_rekey, ShareholderId, Share}).

-spec start_validate_rekey() -> kds_keyring_initializer:encrypted_master_key_shares().
start_validate_rekey() ->
    call(start_validate_rekey).

-spec validate_rekey(kds_shareholder:shareholder_id(), kds_keysharing:masterkey_share()) -> {more, pos_integer()} | ok.
validate_rekey(ShareholderId, Share) ->
    call({validate_rekey, ShareholderId, Share}).

-spec cancel_rekey() -> ok.
cancel_rekey() ->
    call(cancel_rekey).

-spec get_status() -> status().
get_status() ->
    call(get_status).

-spec update_meta(kds_keyring_meta:keyring_meta_diff()) -> ok.
update_meta(KeyringMeta) ->
    call({update_meta, KeyringMeta}).

-spec get_meta() -> kds_keyring_meta:keyring_meta().
get_meta() ->
    call(get_meta).

call(Event) ->
    case gen_statem:call(?STATEM, Event) of
        ok ->
            ok;
        {ok, Reply} ->
            Reply;
        {error, Reason} ->
            throw(Reason)
    end.

%% gen_fsm.

-spec init(_) -> {ok, locked | not_initialized, data()}.
init([]) ->
    try kds_keyring_storage:read() of
        #{meta := KeyringMeta} ->
            {ok, locked, #data{keyring = #{data => undefined, meta => KeyringMeta}}}
    catch
        not_found ->
            {ok, not_initialized, #data{keyring = #{data => undefined, meta => undefined}}}
    end.

-spec handle_event(gen_statem:event_type(), term(), state(), data()) -> gen_statem:event_handler_result(state()).
%% not_initialized events

handle_event({call, From}, {initialize, Threshold}, not_initialized, _StateData) ->
    Result = kds_keyring_initializer:initialize(Threshold),
    {keep_state_and_data, {reply, From, Result}};
handle_event({call, From}, {validate_init, ShareholderId, Share}, not_initialized, StateData) ->
    case kds_keyring_initializer:validate(ShareholderId, Share) of
        {ok, {more, _More}} = Result ->
            {keep_state_and_data, {reply, From, Result}};
        {ok, {done, {EncryptedKeyring, DecryptedKeyring}}} ->
            ok = kds_keyring_storage:create(EncryptedKeyring),
            NewStateData = StateData#data{keyring = DecryptedKeyring},
            {next_state, unlocked, NewStateData, {reply, From, ok}};
        {error, _Error} = Result ->
            {keep_state_and_data, {reply, From, Result}}
    end;
handle_event({call, From}, cancel_init, not_initialized, _StateData) ->
    ok = kds_keyring_initializer:cancel(),
    {keep_state_and_data, {reply, From, ok}};
%% locked events

handle_event({call, From}, start_unlock, locked, _StateData) ->
    Result = kds_keyring_unlocker:initialize(),
    {keep_state_and_data, {reply, From, Result}};
handle_event({call, From}, {confirm_unlock, ShareholderId, Share}, locked, StateData) ->
    LockedKeyring = kds_keyring_storage:read(),
    case kds_keyring_unlocker:confirm(ShareholderId, Share, LockedKeyring) of
        {ok, {more, _More}} = Result ->
            {keep_state_and_data, {reply, From, Result}};
        {ok, {done, Keyring}} ->
            NewStateData = StateData#data{keyring = Keyring},
            {next_state, unlocked, NewStateData, {reply, From, ok}};
        {error, Error} ->
            {keep_state_and_data, {reply, From, {error, Error}}}
    end;
handle_event({call, From}, cancel_unlock, locked, _StateData) ->
    ok = kds_keyring_unlocker:cancel(),
    {keep_state_and_data, {reply, From, ok}};
%% unlocked events

handle_event({call, From}, lock, unlocked, #data{keyring = Keyring} = StateData) ->
    {next_state, locked, StateData#data{keyring = Keyring#{data => undefined}}, {reply, From, ok}};
handle_event({call, From}, get_keyring, unlocked, #data{keyring = Keyring}) ->
    {keep_state_and_data, {reply, From, {ok, Keyring}}};
handle_event({call, From}, start_rotate, unlocked, _StateData) ->
    Result = kds_keyring_rotator:initialize(),
    {keep_state_and_data, {reply, From, Result}};
handle_event(
    {call, From},
    {confirm_rotate, ShareholderId, Share},
    unlocked,
    #data{keyring = OldKeyring} = StateData
) ->
    EncryptedKeyring = kds_keyring_storage:read(),
    case kds_keyring_rotator:confirm(ShareholderId, Share, EncryptedKeyring, OldKeyring) of
        {ok, {more, _More}} = Result ->
            {keep_state_and_data, {reply, From, Result}};
        {ok, {done, {NewEncryptedKeyring, NewKeyring}}} ->
            ok = kds_keyring_storage:update(NewEncryptedKeyring),
            NewStateData = StateData#data{keyring = NewKeyring},
            {keep_state, NewStateData, {reply, From, ok}};
        {error, Error} ->
            {keep_state_and_data, {reply, From, {error, Error}}}
    end;
handle_event({call, From}, cancel_rotate, unlocked, _StateData) ->
    ok = kds_keyring_rotator:cancel(),
    {keep_state_and_data, {reply, From, ok}};
handle_event({call, From}, {start_rekey, Threshold}, unlocked, _StateData) ->
    Result = kds_keyring_rekeyer:initialize(Threshold),
    {keep_state_and_data, {reply, From, Result}};
handle_event({call, From}, {confirm_rekey, ShareholderId, Share}, unlocked, _StateData) ->
    EncryptedKeyring = kds_keyring_storage:read(),
    Result = kds_keyring_rekeyer:confirm(ShareholderId, Share, EncryptedKeyring),
    {keep_state_and_data, {reply, From, Result}};
handle_event({call, From}, start_validate_rekey, unlocked, #data{keyring = Keyring}) ->
    Result = kds_keyring_rekeyer:start_validation(Keyring),
    {keep_state_and_data, {reply, From, Result}};
handle_event({call, From}, {validate_rekey, ShareholderId, Share}, unlocked, #data{keyring = Keyring}) ->
    case kds_keyring_rekeyer:validate(ShareholderId, Share, Keyring) of
        {ok, {more, _More}} = Result ->
            {keep_state_and_data, {reply, From, Result}};
        {ok, {done, EncryptedKeyring}} ->
            ok = kds_keyring_storage:update(EncryptedKeyring),
            {keep_state_and_data, {reply, From, ok}};
        {error, Error} ->
            {keep_state_and_data, {reply, From, {error, Error}}}
    end;
handle_event({call, From}, cancel_rekey, unlocked, _StateData) ->
    ok = kds_keyring_rekeyer:cancel(),
    {keep_state_and_data, {reply, From, ok}};
%% common events

handle_event({call, From}, get_status, State, _Data) ->
    {keep_state_and_data, {reply, From, {ok, generate_status(State)}}};
handle_event({call, From}, {update_meta, _UpdateKeyringMeta}, not_initialized, _StateData) ->
    {keep_state_and_data, {reply, From, {error, {invalid_status, not_initialized}}}};
handle_event(
    {call, From},
    {update_meta, UpdateKeyringMeta},
    _State,
    #data{keyring = #{meta := KeyringMeta} = Keyring} = Data
) ->
    case kds_keyring_meta:update_meta(KeyringMeta, UpdateKeyringMeta) of
        KeyringMeta ->
            {keep_state_and_data, {reply, From, {ok, ok}}};
        NewKeyringMeta ->
            EncryptedKeyring = kds_keyring_storage:read(),
            NewEncryptedKeyring = EncryptedKeyring#{meta => NewKeyringMeta},
            ok = kds_keyring_storage:update(NewEncryptedKeyring),
            NewKeyring = Keyring#{meta => NewKeyringMeta},
            {keep_state, Data#data{keyring = NewKeyring}, {reply, From, {ok, ok}}}
    end;
handle_event({call, From}, get_meta, _State, #data{keyring = #{meta := KeyringMeta}}) ->
    {keep_state_and_data, {reply, From, {ok, KeyringMeta}}};
handle_event({call, From}, _Event, State, _StateData) ->
    {keep_state_and_data, {reply, From, {error, {invalid_status, State}}}}.

-spec generate_status(atom()) -> status().
generate_status(StateName) ->
    #{
        status => StateName,
        activities => #{
            initialization => kds_keyring_initializer:get_status(),
            rotation => kds_keyring_rotator:get_status(),
            unlock => kds_keyring_unlocker:get_status(),
            rekeying => kds_keyring_rekeyer:get_status()
        }
    }.

-spec terminate(term(), atom(), term()) -> ok.
terminate(_Reason, _StateName, _StateData) ->
    ok.

-spec code_change(term(), atom(), data(), term()) -> {ok, atom(), data()}.
code_change(_OldVsn, StateName, StateData, _Extra) ->
    {ok, StateName, StateData}.
