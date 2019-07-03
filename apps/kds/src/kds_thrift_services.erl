-module(kds_thrift_services).

-export([http_handler/1]).
-export([path/1]).
-export([service/1]).

%%
%% Types
%%

-type service_name() :: keyring_management | keyring_storage.

-export_type([service_name/0]).

%%
%% API
%%

-spec http_handler(service_name()) -> woody:http_handler(woody:th_handler()).
http_handler(Code) ->
    {path(Code), {service(Code), handler_module(Code)}}.

-spec path(service_name()) -> woody:path().
path(keyring_management) ->
    "/v2/keyring";
path(keyring_storage) ->
    "/v2/keyring_storage".

-spec service(service_name()) -> woody:service().
service(keyring_management) ->
    {cds_proto_keyring_thrift, 'KeyringManagement'};
service(keyring_storage) ->
    {cds_proto_keyring_thrift, 'KeyringStorage'}.

-spec handler_module(service_name()) -> woody:handler(list()).
handler_module(keyring_management) ->
    {kds_keyring_management_thrift_handler, []};
handler_module(keyring_storage) ->
    {kds_keyring_storage_thrift_handler, []}.
