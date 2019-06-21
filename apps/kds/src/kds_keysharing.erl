-module(kds_keysharing).

-include_lib("shamir/include/shamir.hrl").

-export([share/3]).
-export([recover/1]).
-export([encode_share/1]).
-export([decode_share/1]).
-export([encrypt_shares_for_shareholders/2]).
-export([get_shares/1]).
-export([get_id_map/1]).
-export([validate_shares/2]).
-export([validate_share_combos/1]).

-export_type([masterkey_share/0]).
-export_type([masterkey_shares/0]).
-export_type([signed_masterkey_share/0]).
-export_type([encrypted_master_key_share/0]).
-export_type([encrypted_master_key_shares/0]).
-export_type([masterkey/0]).
-export_type([share_id/0]).
-export_type([threshold/0]).

-type masterkey() :: binary().
-type masterkey_share() :: binary().
-type masterkey_shares() :: [masterkey_share()].
-type masterkey_shares_map() :: #{share_id() => {shareholder_id(), masterkey_share()}}.
-type signed_masterkey_share() :: binary().
-type share_id() :: byte().
-type threshold() :: byte().
-type share() :: #share{
    threshold :: threshold(),
    x :: share_id(),
    y :: binary()
}.

-type shareholder_id() :: kds_shareholder:shareholder_id().
-type shareholder() :: kds_shareholder:shareholder().
-type shareholders() :: kds_shareholder:shareholders().

-type encrypted_master_key_share() :: #{
    id := binary(),
    owner := binary(),
    encrypted_share := binary()
}.
-type encrypted_master_key_shares() :: list(encrypted_master_key_share()).

-spec share(binary(), byte(), byte()) -> [masterkey_share()].
share(Secret, Threshold, Count) ->
    try
        [encode_share(Share) || Share <- shamir:share(Secret, Threshold, Count)]
    catch error:Reason:Stacktrace -> %% FIXME can't catch exact errors because shamir doesn't process them itself
        _ = logger:error("keysharing failed with ~p", [Reason],
            #{stacktrace => genlib_format:format_stacktrace(Stacktrace)}),
        throw(keysharing_failed)
    end.

-spec recover([masterkey_share()] | #{integer() => masterkey_share()}) ->
    {ok, masterkey()} | {error, failed_to_recover}.

recover(Shares) when is_map(Shares) ->
    recover(maps:values(Shares));
recover(Shares) ->
    try
        {ok, shamir:recover([decode_share(Share) || Share <- Shares])}
    catch error:Reason:Stacktrace -> %% FIXME can't catch exact errors because shamir doesn't process them itself
        _ = logger:error("keysharing recover failed ~p", [Reason],
            #{stacktrace => genlib_format:format_stacktrace(Stacktrace)}),
        {error, failed_to_recover}
    end.

-spec encode_share
    (share()) -> masterkey_share().
encode_share(#share{threshold = Threshold, x = X, y = Y}) ->
    base64:encode(<<Threshold, X, Y/binary>>).

-spec decode_share
    (masterkey_share()) -> share().
decode_share(Share) when is_binary(Share) ->
    <<Threshold, X, Y/binary>> = base64:decode(Share),
    #share{threshold = Threshold, x = X, y = Y}.

-spec encrypt_shares_for_shareholders(masterkey_shares(), shareholders()) -> encrypted_master_key_shares().

encrypt_shares_for_shareholders(Shares, Shareholders) ->
    lists:map(fun encrypt_share_for_shareholder/1, lists:zip(Shares, Shareholders)).

-spec encrypt_share_for_shareholder({masterkey_share(), shareholder()}) -> encrypted_master_key_share().

encrypt_share_for_shareholder({Share, #{id := Id, owner := Owner} = Shareholder}) ->
    PublicKey = kds_shareholder:get_public_key(Shareholder, enc),
    #{
        id => Id,
        owner => Owner,
        encrypted_share => kds_crypto:public_encrypt(PublicKey, Share)
    }.

-spec get_shares(masterkey_shares_map()) -> masterkey_shares().

get_shares(Shares) ->
    lists:map(fun ({_ShareholderId, Share}) -> Share end, maps:values(Shares)).

-spec get_id_map(masterkey_shares_map()) -> #{share_id() => shareholder_id()}.

get_id_map(Shares) ->
    maps:map(fun (_K, {ShareholderId, _Share}) -> ShareholderId end, Shares).

-spec validate_shares(threshold(), masterkey_shares()) ->
    {ok, masterkey()} | {error, non_matching_masterkey | failed_to_recover}.

validate_shares(Threshold, Shares) ->
    AllSharesCombos = lib_combin:cnr(Threshold, Shares),
    validate_share_combos(AllSharesCombos).

-spec validate_share_combos([masterkey_shares(), ...]) ->
    {ok, masterkey()} | {error, non_matching_masterkey | failed_to_recover}.

validate_share_combos([FirstCombo | CombosOfShares]) ->
    lists:foldl(
        fun
            (ComboOfShares, {ok, MasterKey}) ->
                case kds_keysharing:recover(ComboOfShares) of
                    {ok, MasterKey} ->
                        {ok, MasterKey};
                    {ok, _NonMatchingMasterkey} ->
                        {error, non_matching_masterkey};
                    {error, failed_to_recover} ->
                        {error, failed_to_recover}
                end;
            (_ComboOfShares, Error) ->
                Error
        end,
        kds_keysharing:recover(FirstCombo),
        CombosOfShares
    ).