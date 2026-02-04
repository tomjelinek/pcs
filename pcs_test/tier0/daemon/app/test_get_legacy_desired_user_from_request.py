import base64
from unittest import TestCase, mock

from pcs.daemon.app.common import get_legacy_desired_user_from_request


class GetLegacyDesiredUserFromRequest(TestCase):
    def setUp(self):
        self.mock_handler = mock.Mock()
        self.mock_logger = mock.Mock(spec_set=["warning"])

    def test_success(self):
        groups_encoded = base64.b64encode(b"haclient wheel square").decode(
            "utf-8"
        )
        self.mock_handler.get_cookie.side_effect = lambda name: {
            "CIB_user": "testuser",
            "CIB_user_groups": groups_encoded,
        }.get(name)

        result = get_legacy_desired_user_from_request(
            self.mock_handler, self.mock_logger
        )
        self.assertEqual(result.username, "testuser")
        self.assertEqual(result.groups, ["haclient", "wheel", "square"])
        self.mock_logger.warning.assert_not_called()

    def test_only_username(self):
        self.mock_handler.get_cookie.side_effect = lambda name: {
            "CIB_user": "testuser"
        }.get(name)

        result = get_legacy_desired_user_from_request(
            self.mock_handler, self.mock_logger
        )
        self.assertEqual(result.username, "testuser")
        self.assertEqual(result.groups, [])
        self.mock_logger.warning.assert_not_called()

    def test_only_groups_ignored(self):
        groups_encoded = base64.b64encode(b"haclient wheel square").decode(
            "utf-8"
        )
        self.mock_handler.get_cookie.side_effect = lambda name: {
            "CIB_user_groups": groups_encoded,
        }.get(name)

        result = get_legacy_desired_user_from_request(
            self.mock_handler, self.mock_logger
        )
        self.assertEqual(result.username, None)
        self.assertEqual(result.groups, [])
        self.mock_logger.warning.assert_not_called()

    def test_invalid_groups(self):
        self.mock_handler.get_cookie.side_effect = lambda name: {
            "CIB_user": "testuser",
            "CIB_user_groups": "this is not a base64 encoded string",
        }.get(name)

        result = get_legacy_desired_user_from_request(
            self.mock_handler, self.mock_logger
        )
        self.assertEqual(result.username, "testuser")
        self.assertEqual(result.groups, [])
        self.mock_logger.warning.assert_called_once_with(
            "Unable to decode desired user groups"
        )
