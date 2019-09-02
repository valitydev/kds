-module(kds).
-behaviour(supervisor).
-behaviour(application).

%% API
-export([start/0]).
-export([stop /0]).

%% Supervisor callbacks
-export([init/1]).

%% Application callbacks
-export([start/2]).
-export([stop /1]).

%%
%% API
%%
-spec start() ->
    {ok, _}.
start() ->
    application:ensure_all_started(kds).

-spec stop() ->
    ok.
stop() ->
    application:stop(kds).


%%
%% Supervisor callbacks
%%

-spec init([]) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init([]) ->
    {ok, IP} = inet:parse_address(application:get_env(kds, ip, "::")),
    HealthCheck = genlib_app:env(?MODULE, health_check, #{}),
    HealthRoute = erl_health_handle:get_route(enable_health_logging(HealthCheck)),
    KeyringManagementService = woody_server:child_spec(
        kds_thrift_management_service_sup,
        #{
            handlers => [
                kds_thrift_services:http_handler(keyring_management)
            ],
            event_handler     => kds_woody_event_handler,
            ip                => IP,
            port              => genlib_app:env(?MODULE, management_port, 8022),
            transport_opts    => genlib_app:env(?MODULE, management_transport_opts, #{}),
            protocol_opts     => genlib_app:env(?MODULE, protocol_opts, #{}),
            shutdown_timeout  => genlib_app:env(?MODULE, shutdown_timeout, 0),
            additional_routes => [HealthRoute]
        }
    ),
    KeyringStorageService = woody_server:child_spec(
        kds_thrift_storage_service_sup,
        #{
            handlers => [
                kds_thrift_services:http_handler(keyring_storage)
            ],
            event_handler     => kds_woody_event_handler,
            ip                => IP,
            port              => genlib_app:env(?MODULE, storage_port, 8023),
            transport_opts    => genlib_app:env(?MODULE, storage_transport_opts, #{}),
            protocol_opts     => genlib_app:env(?MODULE, protocol_opts, #{}),
            shutdown_timeout  => genlib_app:env(?MODULE, shutdown_timeout, 0),
            additional_routes => [HealthRoute]
        }
    ),
    KeyringSupervisor = #{
        id => kds_keyring_sup,
        start => {kds_keyring_sup, start_link, []},
        type => supervisor
    },
    KeyringStorageOpts = genlib_app:env(?MODULE, keyring_storage_opts, #{}),
    KeyringStorage = kds_keyring_storage:child_spec(KeyringStorageOpts),
    Procs = [
        KeyringStorage,
        KeyringSupervisor,
        KeyringManagementService,
        KeyringStorageService
    ],
    {ok, {{one_for_one, 1, 5}, Procs}}.

-spec enable_health_logging(erl_health:check()) -> erl_health:check().
enable_health_logging(Check) ->
    EvHandler = {erl_health_event_handler, []},
    maps:map(fun (_, V = {_, _, _}) -> #{runner => V, event_handler => EvHandler} end, Check).


%%
%% Application callbacks
%%
-spec start(normal, any()) ->
    {ok, pid()} | {error, any()}.
start(normal, _StartArgs) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

-spec stop(any()) ->
    ok.
stop(_State) ->
    ok.
