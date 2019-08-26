-module(kds_keyring_meta).

-include_lib("cds_proto/include/cds_proto_keyring_thrift.hrl").

%% API
-export([get_default_keyring_meta/1]).
-export([update_meta/2]).
-export([decode_keyring_meta_diff/1]).
-export([decode_keyring_meta/1]).
-export([decode_security_parameters/1]).
-export([encode_keyring_meta_diff/1]).
-export([encode_keyring_meta/1]).
-export([encode_security_parameters/1]).

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
        key_id() => key_meta_diff()
    } | undefined
}.
-type key_meta() :: #{
    retired := boolean(),
    security_parameters := security_parameters()
}.
-type key_meta_diff() :: #{
    retired := boolean()
}.
-type security_parameters() :: #{
    deduplication_hash_opts := #{
        n := pos_integer(),
        r := pos_integer(),
        p := pos_integer()
    }
}.
-type key_id() :: kds_keyring:key_id().
-type encoded_keyring_meta() :: #cds_KeyringMeta{}.
-type encoded_keyring_meta_diff() :: #cds_KeyringMetaDiff{}.
-type encoded_security_parameters() :: #cds_SecurityParameters{}.

-define(DEFAULT_SEC_PARAMS, #{
    deduplication_hash_opts => #{
        n => 16384,
        r => 8,
        p => 1
    }
}).
-define(DEFAULT_KEY_META, #{
    retired => false,
    security_parameters => application:get_env(kds, new_key_security_parameters, ?DEFAULT_SEC_PARAMS)
}).

-spec get_default_keyring_meta(kds_keyring:keyring_data()) -> keyring_meta().
get_default_keyring_meta(KeyringData) ->
    Keys = maps:get(keys, KeyringData),
    CurrentKeyId = lists:max(maps:keys(Keys)),
    KeysMeta = maps:map(fun(_KeyId, _Key) -> ?DEFAULT_KEY_META end, Keys),
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
decode_keyring_meta_diff(#cds_KeyringMetaDiff{
    current_key_id = CurrentKeyId,
    keys_meta = KeysMeta
}) ->
    DecodedKeysMeta = decode_keys_meta_diff(KeysMeta),
    #{current_key_id => CurrentKeyId, keys => DecodedKeysMeta}.

-spec decode_keyring_meta(encoded_keyring_meta()) -> keyring_meta().
decode_keyring_meta(#cds_KeyringMeta{
    current_key_id = CurrentKeyId,
    keys_meta = KeysMeta
}) ->
    DecodedKeysMeta = decode_keys_meta(KeysMeta),
    #{current_key_id => CurrentKeyId, version => 1, keys => DecodedKeysMeta}.

decode_keys_meta_diff(undefined) ->
    undefined;
decode_keys_meta_diff(KeysMetaDiff) ->
    maps:fold(
        fun(K, #cds_KeyMetaDiff{retired = Retired}, Acc) ->
            Acc#{K => #{retired => Retired}}
        end,
        #{},
        KeysMetaDiff).

decode_keys_meta(KeysMeta) ->
    maps:fold(
        fun(K,
            #cds_KeyMeta{
                retired = Retired,
                security_parameters = SecurityParameters
            },
            Acc) ->
            Acc#{K => #{
                retired => Retired,
                security_parameters => decode_security_parameters(SecurityParameters)
            }}
        end,
        #{},
        KeysMeta).

-spec decode_security_parameters(encoded_security_parameters()) -> security_parameters().
decode_security_parameters(#cds_SecurityParameters{deduplication_hash_opts = HashOpts}) ->
    #{deduplication_hash_opts => decode_scrypt_opts(HashOpts)}.

decode_scrypt_opts(#cds_ScryptOptions{n = N, r = R, p = P}) ->
    #{n => N, r => R, p => P}.

-spec encode_keyring_meta_diff(keyring_meta_diff()) -> encoded_keyring_meta_diff().
encode_keyring_meta_diff(KeyringMetaDiff) ->
    #cds_KeyringMetaDiff{
        current_key_id = maps:get(current_key_id, KeyringMetaDiff, undefined),
        keys_meta = encode_keys_meta_diff(maps:get(keys, KeyringMetaDiff, undefined))
    }.

-spec encode_keyring_meta(keyring_meta() | undefined) -> encoded_keyring_meta().
encode_keyring_meta(undefined) ->
    #cds_KeyringMeta{current_key_id = 0, keys_meta = #{}};
encode_keyring_meta(#{
    current_key_id := CurrentKeyId,
    keys := KeysMeta
}) ->
    EncodedKeysMeta = encode_keys_meta(KeysMeta),
    #cds_KeyringMeta{current_key_id = CurrentKeyId, keys_meta = EncodedKeysMeta}.

encode_keys_meta_diff(undefined) ->
    undefined;
encode_keys_meta_diff(KeysMetaDiff) ->
    maps:fold(
        fun(K, #{retired := Retired}, Acc) ->
            Acc#{K => #cds_KeyMetaDiff{retired = Retired}}
        end,
        #{},
        KeysMetaDiff
    ).

encode_keys_meta(undefined) ->
    undefined;
encode_keys_meta(KeysMeta) ->
    maps:fold(
        fun(K,
            #{
                retired := Retired,
                security_parameters := SecurityParameters
            },
            Acc) ->
            Acc#{K => #cds_KeyMeta{
                retired = Retired,
                security_parameters = encode_security_parameters(SecurityParameters)
            }}
        end,
        #{},
        KeysMeta
    ).

-spec encode_security_parameters(security_parameters()) -> encoded_security_parameters().
encode_security_parameters(#{deduplication_hash_opts := ScryptOpts}) ->
    #cds_SecurityParameters{deduplication_hash_opts = encode_scrypt_opts(ScryptOpts)}.

encode_scrypt_opts(#{n := N, r := R, p := P}) ->
    #cds_ScryptOptions{n = N, r = R, p = P}.
