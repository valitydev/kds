-module(kds_keyring).

-export([new/0]).
-export([rotate/1]).
-export([get_key/2]).
-export([get_keys/1]).
-export([get_current_key/1]).

-export([encrypt/2]).
-export([decrypt/2]).
-export([marshall/1]).
-export([unmarshall/1]).

-export([validate_masterkey/3]).
-export([validate_masterkey/2]).

-export_type([key/0]).
-export_type([key_id/0]).
-export_type([keyring/0]).
-export_type([keyring_data/0]).
-export_type([encrypted_keyring/0]).

-type masterkey() :: kds_keysharing:masterkey().
-type key() :: binary().
-type key_id() :: byte().
-type encrypted_keyring() :: #{
    data := binary(),
    meta := keyring_meta() | undefined
}.
-type keyring_meta() :: kds_keyring_meta:keyring_meta().

-type keyring() :: #{
    data := keyring_data(),
    meta := keyring_meta()
}.

-type keyring_data() :: #{
    keys := #{key_id() => key()}
}.

-define(KEY_BYTESIZE, 32).
-define(FORMAT_VERSION, 1).
-define(DEFAULT_SEC_PARAMS, #{
    deduplication_hash_opts => #{
        n => 16384,
        r => 8,
        p => 1
    }
}).

%%

-spec new() -> keyring().
new() ->
    SecurityParameters = application:get_env(kds, new_key_security_parameters, ?DEFAULT_SEC_PARAMS),
    #{
        data => #{
            keys => #{0 => kds_crypto:key()}
        },
        meta => #{
            current_key_id => 0,
            version => 1,
            keys => #{
                0 => #{
                    retired => false,
                    security_parameters => SecurityParameters
                }
            }
        }
    }.

-spec rotate(keyring()) -> keyring().
rotate(#{data := #{keys := Keys}, meta := #{current_key_id := CurrentKeyId, version := Version, keys := KeysMeta}}) ->
    MaxKeyId = lists:max(maps:keys(Keys)),
    SecurityParameters = application:get_env(kds, new_key_security_parameters, ?DEFAULT_SEC_PARAMS),
    NewMaxKeyId = MaxKeyId + 1,
    #{
        data => #{
            keys => Keys#{NewMaxKeyId => kds_crypto:key()}
        },
        meta => #{
            current_key_id => CurrentKeyId,
            version => Version + 1,
            keys => KeysMeta#{NewMaxKeyId => #{retired => false, security_parameters => SecurityParameters}}
        }
    }.

-spec get_key(key_id(), keyring()) -> {ok, {key_id(), key()}} | {error, not_found}.
get_key(KeyId, #{data := #{keys := Keys}}) ->
    case maps:find(KeyId, Keys) of
        {ok, Key} ->
            {ok, {KeyId, Key}};
        error ->
            {error, not_found}
    end.

-spec get_keys(keyring()) -> [{key_id(), key()}].
get_keys(#{data := #{keys := Keys}}) ->
    maps:to_list(Keys).

-spec get_current_key(keyring()) -> {key_id(), key()}.
get_current_key(#{data := #{keys := Keys}, meta := #{current_key_id := CurrentKeyId}}) ->
    CurrentKey = maps:get(CurrentKeyId, Keys),
    {CurrentKeyId, CurrentKey}.

%%

-spec encrypt(key(), keyring()) -> encrypted_keyring().
encrypt(MasterKey, #{data := KeyringData, meta := KeyringMeta}) ->
    #{
        data => base64:encode(kds_crypto:encrypt(MasterKey, marshall(KeyringData))),
        meta => KeyringMeta
    }.

-spec decrypt(key(), encrypted_keyring()) -> {ok, keyring()} | {error, decryption_failed}.
decrypt(MasterKey, #{data := EncryptedKeyringData, meta := KeyringMeta}) ->
    case KeyringMeta of
        undefined ->
            try unmarshall(kds_crypto:decrypt(MasterKey, EncryptedKeyringData)) of
                KeyringData ->
                    {ok, #{
                        data => KeyringData,
                        meta => kds_keyring_meta:get_default_keyring_meta(KeyringData)
                    }}
            catch
                decryption_failed ->
                    {error, decryption_failed}
            end;
        _ ->
            try unmarshall(kds_crypto:decrypt(MasterKey, base64:decode(EncryptedKeyringData))) of
                KeyringData ->
                    {ok, #{data => KeyringData, meta => KeyringMeta}}
            catch
                decryption_failed ->
                    {error, decryption_failed}
            end
    end.

-spec marshall(keyring_data()) -> binary().
marshall(#{keys := Keys}) ->
    Keyring = erlang:term_to_binary(#{
        keys => Keys
    }),
    <<?FORMAT_VERSION:8/integer-unit:4, Keyring/binary>>.

-spec unmarshall(binary()) -> keyring_data().
unmarshall(<<MaxKeyId, Keys/binary>> = MarshalledKeyring) ->
    KeysSize = erlang:byte_size(Keys),
    case (KeysSize div 33 =:= (MaxKeyId + 1)) and (KeysSize rem 33 =:= 0) of
        true ->
            #{keys => unmarshall_keys(Keys, #{})};
        false ->
            <<1:8/integer-unit:4, Keyring/binary>> = MarshalledKeyring,
            erlang:binary_to_term(Keyring, [safe])
    end.

-spec unmarshall_keys(binary(), map()) -> map().
unmarshall_keys(<<>>, Acc) ->
    Acc;
unmarshall_keys(<<KeyId, Key:?KEY_BYTESIZE/binary, Rest/binary>>, Acc) ->
    unmarshall_keys(Rest, Acc#{KeyId => Key}).

-spec validate_masterkey(masterkey(), keyring(), encrypted_keyring()) ->
    {ok, keyring()} | {error, wrong_masterkey}.
validate_masterkey(MasterKey, Keyring, EncryptedOldKeyring) ->
    case decrypt(MasterKey, EncryptedOldKeyring) of
        {ok, Keyring} ->
            {ok, Keyring};
        {ok, _NotMatchingKeyring} ->
            {error, wrong_masterkey};
        {error, decryption_failed} ->
            {error, wrong_masterkey}
    end.

-spec validate_masterkey(masterkey(), encrypted_keyring()) ->
    {ok, keyring()} | {error, wrong_masterkey}.
validate_masterkey(MasterKey, EncryptedOldKeyring) ->
    case decrypt(MasterKey, EncryptedOldKeyring) of
        {ok, Keyring} ->
            {ok, Keyring};
        {error, decryption_failed} ->
            {error, wrong_masterkey}
    end.
