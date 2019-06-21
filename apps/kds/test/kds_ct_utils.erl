-module(kds_ct_utils).

-include_lib("common_test/include/ct.hrl").

-export([start_clear/1]).
-export([stop_clear/1]).

-export([store/2]).
-export([store/3]).
-export([lookup/2]).

-export([start_stash/1]).

%%
%% Types
%%

-type config() :: [{atom(), any()}] | atom().

-export_type([config/0]).

%%
%% API
%%

-spec start_clear(config()) -> config().
start_clear(Config) ->
    IP = "127.0.0.1",
    Port = 8022,
    RootUrl = "http://" ++ IP ++ ":" ++ integer_to_list(Port),
    Apps =
        genlib_app:start_application_with(scoper, [
            {storage, scoper_storage_logger}
        ]) ++
        genlib_app:start_application_with(kds, [
            {ip, IP},
            {port, Port},
            {keyring_storage, kds_keyring_storage_file},
            {keyring_storage_opts, #{
                keyring_path => filename:join(config(priv_dir, Config), "keyring")
            }},
            {transport_opts, #{}},
            {protocol_opts, #{
                request_timeout => 60000
            }},
            {shutdown_timeout, 0},
            {keyring_rotation_lifetime, 1000},
            {keyring_unlock_lifetime, 1000},
            {keyring_rekeying_lifetime, 3000},
            {keyring_initialize_lifetime, 3000},
            {shareholders, #{
                <<"1">> => #{
                    owner => <<"ndiezel">>,
                    public_keys => #{
                        enc =>  <<"{
                                        \"use\": \"enc\",
                                        \"kty\": \"RSA\",
                                        \"kid\": \"KUb1fNMc5j9Ei_IV3DguhJh5UOH30uvO7qXq13uevnk\",
                                        \"alg\": \"RSA-OAEP-256\",
                                        \"n\": \"2bxkamUQjD4CN8rcq5BfNLJmRmosb-zY7ajPBJqtiLUTcqym23OkUIA1brBg34clmU2ZQmtd3LWi5kVJk_wr4WsMG_78jHK3wQA-HRhY4WZDZrULTsi4XWpNSwL4dCml4fs536RKy_TyrnpiXg0ug4JVVaEeo7VIZ593mVhCxC8Ev6FK8tZ2HGGOerUXLpgQdhcp9UwaI_l7jgoWNp1f7SuBqv1mfiw4ziC1yvwyXHTKy-37LjLmVB9EVyjqpkwZgzapaOvHc1ABqJpdOrUh-PyOgq-SduqSkMrvqZEdUeR_KbFVxqbxqWJMrqkl2HOJxOla9cHRowg5ObUBjeMoaTJfqie3t6uRUsFEFMzhIyvo6QMYHooxIdOdwpZ4tpzML6jv9o5DPtN375bKzy-UsjeshYbvad1mbrcxc8tYeiQkDZEIM0KeOdHm5C6neEyY6oF4s1vSYBNCnhE5O-R9dmp8Sk5KEseEkOH5u4G2RsIXBA9z1OTDoy6qF21EvRCGzsGfExfkmPAtzbnS-EHHxbMUiio0ZJoZshYo8dwJY6vSN7UsXBgW1v7GvIF9VsfzRmgkl_3rdemYy28DJKC0U2yufePcA3nUJEhtR3UO_tIlHxZvlDSX5eTx4vs5VkFfujNSiPsgH0PEeXABGBFbal7QxU1u0XHXIFwhW5cM8Fs\",
                                        \"e\": \"AQAB\"
                                    }">>,
                        sig =>  <<"{
                                        \"crv\":\"Ed25519\",
                                        \"kid\":\"K3ZpHNJw3IZYu4fefhImUtB47eSBD4nRmpjWIoGukyg\",
                                        \"kty\":\"OKP\",
                                        \"x\":\"hqoiLZvfBzgtFQop3mBzUACee1ycgaT3tJIcKQ2Ndjc\"
                                    }">>
                }},
                <<"2">> => #{
                    owner => <<"ndiezel2">>,
                    public_keys => #{
                        enc =>  <<"{
                                      \"use\": \"enc\",
                                      \"kty\": \"RSA\",
                                      \"kid\": \"JHKqPDhPO8ZnZsloKTHt44UbzYFnKnf_zowfL_zNFRE\",
                                      \"alg\": \"RSA-OAEP-256\",
                                      \"n\": \"5vIJr6yv-ipphJf8Saam2-bmB5lab7tzlGOoI6uU60x_yBfc58ttzoT__nz8UM0ZmW6k22YvMvnOvmNoPNM0rD_u7M8HGEjZyOlel64PVuv7eqU0-217JbjJ99iMbGagQkgGyyVRfS1sF9fqig79Pn7_4-bcY8-f1bZahgaDqimikfSWu00kvHwnQPNICC_xY7gtT1K40IlQcPG-XBGMrK3JXgEmTKYaNB6TS9MX20vEkcnhYzl6AeU_dj83IXuR_fw_qLqmY6rZjHWVrSvarsUIlVN3ti1Zs53eUwjv4r-wN4oK9NPNcTvAijeq85OH5DbN9ZyPTTJKcqq1Q-M2AaMTSIQCCs260CmL9Nn0M3b6eDglZumqMkCc5p_xPmNgtiFAu0_mLf3lk9MKwd2635Tz6tZO7Di77UrClTnneu1Du5VBt7v8-xIZWL11xXHaglpIwi7SLFOl_YRk6vKzjvt0pYe7N-y9T0MSTdDkB_it7Tt7rtltMYnTA8HZTlRC6EoFMj4e7bpM8iizxl6Hbg3lj0fb24kNbI4P7cV-Y6-81NLBu0Yi0H4J-b7Km_NU1tmK1SCLxzFqhCtQXg7JhJUY-gXdMgbdLyY5zrawkwsJhq_Lpsk6dHQsxV35imi7kNkOTnoiI-SpswrACIlThnT56xC5ROuFRxAlrpZef-c\",
                                      \"e\": \"AQAB\"
                                    }">>,
                        sig =>  <<"{
                                        \"crv\":\"Ed25519\",
                                        \"kid\":\"Q_85NCYwrmJr1vcbPOzO8g31_ohqFLpVoaGysWPwCbc\",
                                        \"kty\":\"OKP\",
                                        \"x\":\"JhVaGPlRm67u0oGbgxAgqnfLfXeW0aGjhCrBf_C1Fiw\"
                                    }">>
                }},
                <<"3">> => #{
                    owner => <<"ndiezel3">>,
                    public_keys => #{
                        enc =>  <<"{
                                      \"use\": \"enc\",
                                      \"kty\": \"RSA\",
                                      \"kid\": \"xBET5c4u0yT6pDb_Cok0exHe_wQVetVpkGKn_1mmn7A\",
                                      \"alg\": \"RSA-OAEP-256\",
                                      \"n\": \"qR8UeoACkdiKllzYR6KSqldMqeA_RkVePp1DKWXCRKDKrw3OieX81tmQmbBkcisnpSipTvezmr2-6t0sPELZeah3r1-qUwQeD2ugSicoqgQoqgLT7g9DHVF8NBvHbAgESJoq-1dJqepG8-jrwT5UGioE9SGowRVywrndUjdWrKyfDPiwzSALtV5mcpZi97M_ga5J1gNJFT0h1E2QbYkdEBeDsyatcJu_-LtEuCJN0DKUhvNeXVdIcnbwxFXtmx4dmxPUDG7a03bo2_Ni3-ZdvHmtkleHvWBn2LI_zArCIZdAMsA9HJiT8DrEuLXJ-pHhx2z6wJ9l8y7QSDTtKZE0GyNpCUHtzDfwfRS0GPdj2ntIHyBO8RZqDhWc3_FH9IxQYED5UnwP5Z-VodJ0ZIStNPNGtSs1hdnW3nyAFaP9T3X5UWhHsSGjq9pDm-Lroe4jJK4uKRa__ewIB8Szfp-NgG2SGeWhpETZSDwDYEYzMZncsp35GByj7YqmrpKqAHkTsTfkbCWHgN9wUqX1vjsPUtgHB4l_Ze1G_m__-URyu8qrDR11vzqMA-iY8aSQ7DpHoRp7fThVD7gJIQNyVyAzIvDyOVdSmUPPeGxnI1YWKX-5t5SnlnpWO1Rqqh6RBtxu_1JGfq77d2khskTaPXxc1E5iyCYLFI0UgreCXpBzSGU\",
                                      \"e\": \"AQAB\"
                                    }">>,
                        sig =>  <<"{
                                        \"crv\":\"Ed25519\",
                                        \"kid\":\"nwy3plcwQj_b70JJ3maZkN-VFQpjGCVRyIFYNeC0vvs\",
                                        \"kty\":\"OKP\",
                                        \"x\":\"af4UVYqUB4g711yGxzKjWvd27c9WY1EQ1a1-fwk0A6w\"
                                    }">>
                }}
            }}
        ]),
    [
        {apps, lists:reverse(Apps)},
        {root_url, genlib:to_binary(RootUrl)}
    ] ++ Config.

-spec stop_clear(config()) -> ok.
stop_clear(C) ->
    _ = (catch kds_keyring_storage_file:delete()),
    [ok = application:stop(App) || App <- config(apps, C)],
    stop_stash(C).

-spec store([{any(), any()}], config()) -> ok.
store(KVs, C) when is_list(KVs) ->
    [store(Key, Value, C) || {Key, Value} <- KVs],
    ok.

-spec store(any(), any(), config()) -> ok.
store(Key, Value, C) ->
    kds_ct_stash:put(config(stash, C), Key, Value).

-spec lookup(any(), config()) -> any().
lookup(Key, C) ->
    kds_ct_stash:get(config(stash, C), Key).

-spec start_stash(config()) -> config().
start_stash(C) ->
    [
        {stash, kds_ct_stash:start()}
    ] ++ C.

%%
%% Internals
%%

config(Key, Config) ->
    config(Key, Config, undefined).

config(Key, Config, Default) ->
    case lists:keysearch(Key, 1, Config) of
        {value, {Key, Val}} ->
            Val;
        _ ->
            Default
    end.

stop_stash(C) ->
    kds_ct_stash:stop(config(stash, C)).
