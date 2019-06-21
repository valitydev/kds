-module(kds_thrift_services).

-export([http_handler/1]).
-export([path/1]).
-export([service/1]).

%%
%% Types
%%

-type service_name() :: keyring_v2.

-export_type([service_name/0]).

%%
%% API
%%

-spec http_handler(service_name()) -> woody:http_handler(woody:th_handler()).
http_handler(Code) ->
    {path(Code), {service(Code), handler_module(Code)}}.

-spec path(service_name()) -> woody:path().
path(keyring_v2) ->
    "/v2/keyring".

-spec service(service_name()) -> woody:service().
service(keyring_v2) ->
    {cds_proto_keyring_thrift, 'Keyring'}.

-spec handler_module(service_name()) -> woody:handler(list()).
handler_module(keyring_v2) ->
    {kds_keyring_v2_thrift_handler, []}.
