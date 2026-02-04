from tornado.ioloop import IOLoop
from tornado.web import HTTPError

from pcs.daemon.app.auth_provider import (
    ApiAuthProviderFactoryInterface,
    ApiAuthProviderInterface,
    NotAuthorizedException,
)
from pcs.lib.auth.provider import AuthProvider

from .common import LegacyApiHandler, RoutesType


class LegacyAuth(LegacyApiHandler):
    _lib_auth_provider: AuthProvider

    def initialize(self, lib_auth_provider: AuthProvider) -> None:
        super().initialize()
        self._lib_auth_provider = lib_auth_provider

    async def auth(self) -> None:
        auth_user = await IOLoop.current().run_in_executor(
            executor=None,
            func=lambda: self._lib_auth_provider.auth_by_username_password(
                self.get_body_argument("username") or "",
                self.get_body_argument("password") or "",
            ),
        )
        if auth_user is None:
            # To stay backward compatible with original ruby implementation,
            # an empty response needs to be returned if authentication fails
            return

        token = await IOLoop.current().run_in_executor(
            executor=None,
            func=lambda: self._lib_auth_provider.create_token(
                auth_user.username
            ),
        )
        if token:
            self.write(token)
        else:
            raise HTTPError(400, reason="Unable to store token")

    async def _handle_request(self) -> None:
        await self.auth()


class CheckAuth(LegacyApiHandler):
    _auth_provider: ApiAuthProviderInterface

    def initialize(
        self, api_auth_provider_factory: ApiAuthProviderFactoryInterface
    ) -> None:
        self._auth_provider = api_auth_provider_factory.create(self)

    async def _handle_request(self) -> None:
        if not self._auth_provider.can_handle_request():
            raise self.unauthorized()

        try:
            await self._auth_provider.auth_user()
        except NotAuthorizedException as e:
            raise self.unauthorized() from e

        self.write('{"success":true}')


def get_routes(
    lib_auth_provider: AuthProvider,
    api_auth_provider_factory: ApiAuthProviderFactoryInterface,
) -> RoutesType:
    return [
        ("/remote/auth", LegacyAuth, dict(lib_auth_provider=lib_auth_provider)),
        (
            "/remote/check_auth",
            CheckAuth,
            dict(api_auth_provider_factory=api_auth_provider_factory),
        ),
    ]
