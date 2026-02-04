import logging
from unittest import mock

from pcs.daemon.app import auth
from pcs.lib.auth.provider import AuthProvider
from pcs.lib.auth.types import AuthUser

from pcs_test.tier0.daemon.app import fixtures_app
from pcs_test.tier0.daemon.app.fixtures_app_api import MockAuthProviderFactory

# Don't write errors to test output.
logging.getLogger("tornado.access").setLevel(logging.CRITICAL)


class Auth(fixtures_app.AppTest):
    def setUp(self):
        self.lib_auth_provider = AuthProvider(logging.getLogger("test logger"))
        self.auth_provider_mock = self._mock_auth_provider_method(
            "auth_by_username_password"
        )
        self.token = "new token"
        self._mock_auth_provider_method("create_token", self.token)
        super().setUp()

    def get_routes(self):
        return auth.get_routes(self.lib_auth_provider, None)

    def _mock_auth_provider_method(self, method_name, return_value=None):
        method_patcher = mock.patch.object(AuthProvider, method_name)
        self.addCleanup(method_patcher.stop)
        method_mock = method_patcher.start()
        if return_value:
            method_mock.return_value = return_value
        return method_mock

    def make_auth_request(self):
        return self.post(
            "/remote/auth",
            body={
                "username": fixtures_app.USER,
                "password": fixtures_app.PASSWORD,
            },
        )

    def test_refuse_unknown_user(self):
        self.auth_provider_mock.return_value = None
        self.assertEqual(b"", self.make_auth_request().body)
        self.auth_provider_mock.assert_called_once_with(
            fixtures_app.USER, fixtures_app.PASSWORD
        )

    def test_success(self):
        self.auth_provider_mock.return_value = AuthUser(
            fixtures_app.USER, fixtures_app.GROUPS
        )
        self.assertEqual(
            self.token.encode("utf-8"), self.make_auth_request().body
        )
        self.auth_provider_mock.assert_called_once_with(
            fixtures_app.USER, fixtures_app.PASSWORD
        )


class CheckAuth(fixtures_app.AppTest):
    def setUp(self):
        self.api_auth_provider_factory_mock = MockAuthProviderFactory()
        super().setUp()

    def get_routes(self):
        return auth.get_routes(None, self.api_auth_provider_factory_mock)

    def make_request(self):
        return self.get("/remote/check_auth")

    def test_success(self):
        response = self.make_request()

        self.assertEqual(response.code, 200)
        self.assertEqual(response.body, b'{"success":true}')
        self.api_auth_provider_factory_mock.provider.can_handle_request.assert_called_once_with()
        self.api_auth_provider_factory_mock.provider.auth_user.assert_called_once_with()

    def test_auth_cannot_handler_request(self):
        self.api_auth_provider_factory_mock.auth_result = (
            "cannot_handle_request"
        )

        response = self.make_request()

        self.assertEqual(response.code, 401)
        self.assertEqual(response.body, b'{"notauthorized":"true"}')
        self.api_auth_provider_factory_mock.provider.can_handle_request.assert_called_once_with()
        self.api_auth_provider_factory_mock.provider.auth_user.assert_not_called()

    def test_auth_not_authorized(self):
        self.api_auth_provider_factory_mock.auth_result = "not_authorized"

        response = self.make_request()

        self.assertEqual(response.code, 401)
        self.assertEqual(response.body, b'{"notauthorized":"true"}')
        self.api_auth_provider_factory_mock.provider.can_handle_request.assert_called_once_with()
        self.api_auth_provider_factory_mock.provider.auth_user.assert_called_once_with()
