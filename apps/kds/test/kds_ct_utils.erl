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
    ManagementPort = 8022,
    StoragePort = 8023,
    ManagementRootUrl = "http://" ++ IP ++ ":" ++ integer_to_list(ManagementPort),
    StorageRootUrl = "https://" ++ IP ++ ":" ++ integer_to_list(StoragePort),
    CACertFile = filename:join(config(data_dir, Config), "ca.crt"),
    ServerCertFile = filename:join(config(data_dir, Config), "server.pem"),
    ClientCertFile = filename:join(config(data_dir, Config), "client.pem"),
    Apps =
        genlib_app:start_application_with(kernel, [
            {logger_sasl_compatible, false},
            {logger_level, debug},
            {logger, [
                {handler, default, logger_std_h, #{
                    formatter =>
                        {logger_logstash_formatter, #{
                            message_redaction_regex_list => [
                                %% pan
                                "[0-9]{12,19}",
                                %% expiration date
                                "[0-9]{2}.[0-9]{2,4}",
                                %% cvv
                                "[0-9]{3,4}",
                                %% JWS and JWE compact representation
                                "^ey[JI]([a-zA-Z0-9_-]*.?){1,6}"
                            ]
                        }}
                }}
            ]}
        ]) ++
            genlib_app:start_application_with(scoper, [
                {storage, scoper_storage_logger}
            ]) ++
            genlib_app:start_application_with(os_mon, [
                {start_disksup, false},
                {start_memsup, false},
                {start_cpu_sup, false}
            ]) ++
            genlib_app:start_application_with(kds, [
                {ip, IP},
                {management_port, ManagementPort},
                {storage_port, StoragePort},
                {keyring_storage, kds_keyring_storage_file},
                {keyring_storage_opts, #{
                    keyring_path => filename:join(config(priv_dir, Config), "keyring")
                }},
                {management_transport_opts, #{}},
                {storage_transport_opts, #{
                    transport => ranch_ssl,
                    socket_opts => [
                        {cacertfile, CACertFile},
                        {certfile, ServerCertFile},
                        {verify, verify_peer},
                        {fail_if_no_peer_cert, true}
                    ]
                }},
                {new_key_security_parameters, #{
                    deduplication_hash_opts => #{
                        n => 16384,
                        r => 8,
                        p => 1
                    }
                }},
                {protocol_opts, #{
                    request_timeout => 60000
                }},
                {shutdown_timeout, 0},
                {keyring_rotation_lifetime, 1000},
                {keyring_unlock_lifetime, 1000},
                {keyring_rekeying_lifetime, 5000},
                {keyring_initialize_lifetime, 4000},
                {shareholders, #{
                    <<"1">> => #{
                        owner => <<"ndiezel">>,
                        public_keys => #{
                            enc =>
                                <<"{\n"
                                    "\"use\": \"enc\",\n"
                                    "\"kty\": \"RSA\",\n"
                                    "\"kid\": \"KUb1fNMc5j9Ei_IV3DguhJh5UOH30uvO7qXq13uevnk\",\n"
                                    "\"alg\": \"RSA-OAEP-256\",\n"
                                    "\"n\": \"2bxkamUQjD4CN8rcq5BfNLJmRmosb-zY7ajPBJqtiLUTcqym23O"
                                    "kUIA1brBg34clmU2ZQmtd3LWi5kVJk_wr4WsMG_78jHK3wQA-HRhY4WZDZrU"
                                    "LTsi4XWpNSwL4dCml4fs536RKy_TyrnpiXg0ug4JVVaEeo7VIZ593mVhCxC8"
                                    "Ev6FK8tZ2HGGOerUXLpgQdhcp9UwaI_l7jgoWNp1f7SuBqv1mfiw4ziC1yvw"
                                    "yXHTKy-37LjLmVB9EVyjqpkwZgzapaOvHc1ABqJpdOrUh-PyOgq-SduqSkMr"
                                    "vqZEdUeR_KbFVxqbxqWJMrqkl2HOJxOla9cHRowg5ObUBjeMoaTJfqie3t6u"
                                    "RUsFEFMzhIyvo6QMYHooxIdOdwpZ4tpzML6jv9o5DPtN375bKzy-UsjeshYb"
                                    "vad1mbrcxc8tYeiQkDZEIM0KeOdHm5C6neEyY6oF4s1vSYBNCnhE5O-R9dmp"
                                    "8Sk5KEseEkOH5u4G2RsIXBA9z1OTDoy6qF21EvRCGzsGfExfkmPAtzbnS-EH"
                                    "HxbMUiio0ZJoZshYo8dwJY6vSN7UsXBgW1v7GvIF9VsfzRmgkl_3rdemYy28"
                                    "DJKC0U2yufePcA3nUJEhtR3UO_tIlHxZvlDSX5eTx4vs5VkFfujNSiPsgH0P"
                                    "EeXABGBFbal7QxU1u0XHXIFwhW5cM8Fs\",\n"
                                    "\"e\": \"AQAB\"\n"
                                    "}">>,
                            sig =>
                                <<"{\n"
                                    "\"crv\":\"Ed25519\",\n"
                                    "\"kid\":\"K3ZpHNJw3IZYu4fefhImUtB47eSBD4nRmpjWIoGukyg\",\n"
                                    "\"kty\":\"OKP\",\n"
                                    "\"x\":\"hqoiLZvfBzgtFQop3mBzUACee1ycgaT3tJIcKQ2Ndjc\"\n"
                                    "}">>
                        }
                    },
                    <<"2">> => #{
                        owner => <<"ndiezel2">>,
                        public_keys => #{
                            enc =>
                                <<"{\n"
                                    "\"use\": \"enc\",\n"
                                    "\"kty\": \"RSA\",\n"
                                    "\"kid\": \"JHKqPDhPO8ZnZsloKTHt44UbzYFnKnf_zowfL_zNFRE\",\n"
                                    "\"alg\": \"RSA-OAEP-256\",\n"
                                    "\"n\": \"5vIJr6yv-ipphJf8Saam2-bmB5lab7tzlGOoI6uU60x_yBfc58t"
                                    "tzoT__nz8UM0ZmW6k22YvMvnOvmNoPNM0rD_u7M8HGEjZyOlel64PVuv7eqU"
                                    "0-217JbjJ99iMbGagQkgGyyVRfS1sF9fqig79Pn7_4-bcY8-f1bZahgaDqim"
                                    "ikfSWu00kvHwnQPNICC_xY7gtT1K40IlQcPG-XBGMrK3JXgEmTKYaNB6TS9M"
                                    "X20vEkcnhYzl6AeU_dj83IXuR_fw_qLqmY6rZjHWVrSvarsUIlVN3ti1Zs53"
                                    "eUwjv4r-wN4oK9NPNcTvAijeq85OH5DbN9ZyPTTJKcqq1Q-M2AaMTSIQCCs2"
                                    "60CmL9Nn0M3b6eDglZumqMkCc5p_xPmNgtiFAu0_mLf3lk9MKwd2635Tz6tZ"
                                    "O7Di77UrClTnneu1Du5VBt7v8-xIZWL11xXHaglpIwi7SLFOl_YRk6vKzjvt"
                                    "0pYe7N-y9T0MSTdDkB_it7Tt7rtltMYnTA8HZTlRC6EoFMj4e7bpM8iizxl6"
                                    "Hbg3lj0fb24kNbI4P7cV-Y6-81NLBu0Yi0H4J-b7Km_NU1tmK1SCLxzFqhCt"
                                    "QXg7JhJUY-gXdMgbdLyY5zrawkwsJhq_Lpsk6dHQsxV35imi7kNkOTnoiI-S"
                                    "pswrACIlThnT56xC5ROuFRxAlrpZef-c\",\n"
                                    "\"e\": \"AQAB\"\n"
                                    "}">>,
                            sig =>
                                <<"{\n"
                                    "\"crv\":\"Ed25519\",\n"
                                    "\"kid\":\"Q_85NCYwrmJr1vcbPOzO8g31_ohqFLpVoaGysWPwCbc\",\n"
                                    "\"kty\":\"OKP\",\n"
                                    "\"x\":\"JhVaGPlRm67u0oGbgxAgqnfLfXeW0aGjhCrBf_C1Fiw\"\n"
                                    "}">>
                        }
                    },
                    <<"3">> => #{
                        owner => <<"ndiezel3">>,
                        public_keys => #{
                            enc =>
                                <<"{\n"
                                    "\"use\": \"enc\",\n"
                                    "\"kty\": \"RSA\",\n"
                                    "\"kid\": \"xBET5c4u0yT6pDb_Cok0exHe_wQVetVpkGKn_1mmn7A\",\n"
                                    "\"alg\": \"RSA-OAEP-256\",\n"
                                    "\"n\": \"qR8UeoACkdiKllzYR6KSqldMqeA_RkVePp1DKWXCRKDKrw3OieX"
                                    "81tmQmbBkcisnpSipTvezmr2-6t0sPELZeah3r1-qUwQeD2ugSicoqgQoqgL"
                                    "T7g9DHVF8NBvHbAgESJoq-1dJqepG8-jrwT5UGioE9SGowRVywrndUjdWrKy"
                                    "fDPiwzSALtV5mcpZi97M_ga5J1gNJFT0h1E2QbYkdEBeDsyatcJu_-LtEuCJ"
                                    "N0DKUhvNeXVdIcnbwxFXtmx4dmxPUDG7a03bo2_Ni3-ZdvHmtkleHvWBn2LI"
                                    "_zArCIZdAMsA9HJiT8DrEuLXJ-pHhx2z6wJ9l8y7QSDTtKZE0GyNpCUHtzDf"
                                    "wfRS0GPdj2ntIHyBO8RZqDhWc3_FH9IxQYED5UnwP5Z-VodJ0ZIStNPNGtSs"
                                    "1hdnW3nyAFaP9T3X5UWhHsSGjq9pDm-Lroe4jJK4uKRa__ewIB8Szfp-NgG2"
                                    "SGeWhpETZSDwDYEYzMZncsp35GByj7YqmrpKqAHkTsTfkbCWHgN9wUqX1vjs"
                                    "PUtgHB4l_Ze1G_m__-URyu8qrDR11vzqMA-iY8aSQ7DpHoRp7fThVD7gJIQN"
                                    "yVyAzIvDyOVdSmUPPeGxnI1YWKX-5t5SnlnpWO1Rqqh6RBtxu_1JGfq77d2k"
                                    "hskTaPXxc1E5iyCYLFI0UgreCXpBzSGU\",\n"
                                    "\"e\": \"AQAB\"\n"
                                    "}">>,
                            sig =>
                                <<"{\n"
                                    "\"crv\":\"Ed25519\",\n"
                                    "\"kid\":\"nwy3plcwQj_b70JJ3maZkN-VFQpjGCVRyIFYNeC0vvs\",\n"
                                    "\"kty\":\"OKP\",\n"
                                    "\"x\":\"af4UVYqUB4g711yGxzKjWvd27c9WY1EQ1a1-fwk0A6w\"\n"
                                    "}">>
                        }
                    }
                }}
            ]),
    [
        {apps, lists:reverse(Apps)},
        {management_root_url, genlib:to_binary(ManagementRootUrl)},
        {storage_root_url, genlib:to_binary(StorageRootUrl)},
        {cacertfile, CACertFile},
        {clientcertfile, ClientCertFile}
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
