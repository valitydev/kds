-module(kds_keyring_storage).

-callback child_spec(map()) -> {ok, supervisor:child_spec()}.
-callback create(kds_keyring:encrypted_keyring()) -> ok | {error, already_exists}.
-callback read() -> {ok, kds_keyring:encrypted_keyring()} | {error, not_found}.
-callback update(kds_keyring:encrypted_keyring()) -> ok.
-callback delete() -> ok.

-export([child_spec/1]).
-export([create/1]).
-export([read/0]).
-export([update/1]).
-export([delete/0]).

-spec child_spec(map()) -> supervisor:child_spec().
child_spec(StorageOpts) ->
    kds_backend:call(keyring_storage, child_spec, [StorageOpts]).

-spec create(kds_keyring:encrypted_keyring()) -> ok.
create(Keyring) ->
    kds_backend:call(keyring_storage, create, [Keyring]).

-spec read() -> kds_keyring:encrypted_keyring().
read() ->
    kds_backend:call(keyring_storage, read, []).

-spec update(kds_keyring:encrypted_keyring()) -> ok.
update(Keyring) ->
    kds_backend:call(keyring_storage, update, [Keyring]).

-spec delete() -> ok.
delete() ->
    kds_backend:call(keyring_storage, delete, []).
