from pcs.daemon import ruby_pcsd
from pcs.daemon.app.auth_provider import (
    ApiAuthProviderFactoryInterface,
    ApiAuthProviderInterface,
    NotAuthorizedException,
)
from pcs.daemon.app.common import LegacyApiHandler, RoutesType
from pcs.daemon.app.sinatra_common import SinatraMixin
from pcs.daemon.app.ui_common import AjaxMixin
from pcs.lib.auth.types import AuthUser


class SinatraAjaxProtected(LegacyApiHandler, SinatraMixin, AjaxMixin):
    """
    SinatraAjaxProtected handles urls that calls the ajax Sinatra GUI functions.
    It allows to use this urls only for ajax calls.
    """

    _auth_provider: ApiAuthProviderInterface
    _auth_user: AuthUser

    def initialize(
        self,
        ruby_pcsd_wrapper: ruby_pcsd.Wrapper,
        api_auth_provider_factory: ApiAuthProviderFactoryInterface,
    ) -> None:
        self.initialize_sinatra(ruby_pcsd_wrapper)
        self._auth_provider = api_auth_provider_factory.create(self)

    async def prepare(self) -> None:
        if not self.is_ajax:
            raise self.unauthorized()
        if not self._auth_provider.can_handle_request():
            raise self.unauthorized()
        try:
            self._auth_user = await self._auth_provider.auth_user()
        except NotAuthorizedException as e:
            raise self.unauthorized() from e

    async def _handle_request(self) -> None:
        result = await self.ruby_pcsd_wrapper.request(
            self._auth_user, self.request
        )
        self.send_sinatra_result(result)


def get_routes(
    api_auth_provider_factory: ApiAuthProviderFactoryInterface,
    ruby_pcsd_wrapper: ruby_pcsd.Wrapper,
) -> RoutesType:
    return [
        # The protection by session was moved from ruby code to python code
        # (tornado).
        (
            r"/.*",
            SinatraAjaxProtected,
            dict(
                ruby_pcsd_wrapper=ruby_pcsd_wrapper,
                api_auth_provider_factory=api_auth_provider_factory,
            ),
        ),
    ]
