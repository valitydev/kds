-module(kds_keyring_meta).

-include_lib("cds_proto/include/cds_proto_keyring_thrift.hrl").

%% API
-export([get_default_keyring_meta/1]).
-export([update_meta/2]).
-export([decode_keyring_meta_diff/1]).
-export([decode_keyring_meta/1]).
-export([encode_keyring_meta_diff/1]).
-export([encode_keyring_meta/1]).

-export_type([keyring_meta/0]).
-export_type([keyring_meta_diff/0]).

-type keyring_meta() :: #{
    current_key_id := non_neg_integer(),
    version := pos_integer(),
    keys := #{
        key_id() => key_meta()
    }
}.
-type keyring_meta_diff() :: #{
    current_key_id => non_neg_integer() | undefined,
    keys => #{
        key_id() => key_meta()
    } | undefined
}.
-type key_meta() :: #{
    retired := boolean()
}.
-type key_id() :: kds_keyring:key_id().
-type encoded_keyring_meta() :: #'KeyringMeta'{}.
-type encoded_keyring_meta_diff() :: #'KeyringMetaDiff'{}.

-spec get_default_keyring_meta(kds_keyring:keyring_data()) -> keyring_meta().
get_default_keyring_meta(KeyringData) ->
    Keys = maps:get(keys, KeyringData),
    CurrentKeyId = lists:max(maps:keys(Keys)),
    KeysMeta = maps:map(fun (_KeyId, _Key) -> #{retired => false} end, Keys),
    #{current_key_id => CurrentKeyId, version => 1, keys => KeysMeta}.

-spec update_meta(keyring_meta(), keyring_meta_diff()) -> keyring_meta().
update_meta(#{current_key_id := OldCurrentKeyId, version := Version, keys := OldKeysMeta} = OldMeta, UpdateMeta) ->
    KeysMeta = maps:get(keys, UpdateMeta, undefined),
    UpdatedKeysMeta = update_keys_meta(OldKeysMeta, KeysMeta),
    CurrentKeyId = maps:get(current_key_id, UpdateMeta, undefined),
    UpdatedCurrentKeyId = update_current_key_id(OldCurrentKeyId, CurrentKeyId),
    case OldMeta#{current_key_id => UpdatedCurrentKeyId, keys => UpdatedKeysMeta} of
        OldMeta ->
            OldMeta;
        NewMeta ->
            NewMeta#{version => Version + 1}
    end.

update_keys_meta(OldKeysMeta, undefined) ->
    OldKeysMeta;
update_keys_meta(OldKeysMeta, UpdateKeysMeta) ->
    maps:fold(
        fun(K, V, Acc) ->
            UpdateKeyMeta = maps:get(K, UpdateKeysMeta, #{}),
            Acc#{K => maps:merge(V, UpdateKeyMeta)}
        end,
        #{}, OldKeysMeta).

update_current_key_id(OldCurrentKeyId, undefined) ->
    OldCurrentKeyId;
update_current_key_id(_OldCurrentKeyId, NewCurrentKeyId) ->
    NewCurrentKeyId.

-spec decode_keyring_meta_diff(encoded_keyring_meta_diff()) -> keyring_meta_diff().
decode_keyring_meta_diff(#'KeyringMetaDiff'{
    current_key_id = CurrentKeyId,
    keys_meta = KeysMeta
}) ->
    DecodedKeysMeta = decode_keys_meta(KeysMeta),
    #{current_key_id => CurrentKeyId, keys => DecodedKeysMeta}.

-spec decode_keyring_meta(encoded_keyring_meta()) -> keyring_meta().
decode_keyring_meta(#'KeyringMeta'{
    current_key_id = CurrentKeyId,
    keys_meta = KeysMeta
}) ->
    DecodedKeysMeta = decode_keys_meta(KeysMeta),
    #{current_key_id => CurrentKeyId, version => 1, keys => DecodedKeysMeta}.

decode_keys_meta(undefined) ->
    undefined;
decode_keys_meta(KeysMeta) ->
    maps:fold(
        fun (K, #'KeyMeta'{retired = Retired}, Acc) ->
            Acc#{K => #{retired => Retired}}
        end,
        #{},
        KeysMeta).

-spec encode_keyring_meta_diff(keyring_meta_diff()) -> encoded_keyring_meta_diff().
encode_keyring_meta_diff(KeyringMetaDiff) ->
    #'KeyringMetaDiff'{
        current_key_id = maps:get(current_key_id, KeyringMetaDiff, undefined),
        keys_meta = encode_keys_meta(maps:get(keys, KeyringMetaDiff, undefined))
    }.

-spec encode_keyring_meta(keyring_meta() | undefined) -> encoded_keyring_meta().
encode_keyring_meta(undefined) ->
    #'KeyringMeta'{current_key_id = 0, keys_meta = #{}};
encode_keyring_meta(#{
    current_key_id := CurrentKeyId,
    keys := KeysMeta
}) ->
    EncodedKeysMeta = encode_keys_meta(KeysMeta),
    #'KeyringMeta'{current_key_id = CurrentKeyId, keys_meta = EncodedKeysMeta}.


encode_keys_meta(undefined) ->
    undefined;
encode_keys_meta(KeysMeta) ->
    maps:fold(
        fun (K, #{retired := Retired}, Acc) ->
            Acc#{K => #'KeyMeta'{retired = Retired}}
        end,
        #{},
        KeysMeta
    ).