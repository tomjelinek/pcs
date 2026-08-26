from unittest import TestCase

from pcs.common import reports
from pcs.lib.corosync import config_validators

from pcs_test.tier0.lib.corosync.test_config_validators_common import (
    TotemBase,
    TransportKnetBase,
    TransportUdpBase,
)
from pcs_test.tools import fixture
from pcs_test.tools.assertions import assert_report_item_list_equal


class UpdateTotem(TotemBase, TestCase):
    def call_function(self, options):
        return config_validators.update_totem(options)

    def test_empty_values_allowed(self):
        assert_report_item_list_equal(
            self.call_function(dict.fromkeys(self.allowed_options, "")),
            [],
        )


class UpdateTransportKnet(TransportKnetBase, TestCase):
    def call_function(
        self,
        generic_options,
        compression_options,
        crypto_options,
    ):
        return config_validators.update_transport_knet(
            generic_options, compression_options, crypto_options
        )

    def test_empty_values_allowed(self):
        assert_report_item_list_equal(
            self.call_function(
                {
                    "ip_version": "",
                    "knet_pmtud_interval": "",
                    "link_mode": "",
                },
                {
                    "level": "",
                    "model": "",
                    "threshold": "",
                },
                {
                    "cipher": "",
                    "hash": "",
                    "model": "",
                },
            ),
            [
                fixture.error(
                    reports.codes.INVALID_OPTION_VALUE,
                    option_value="",
                    option_name="cipher",
                    allowed_values=("aes256", "aes192", "aes128"),
                    cannot_be_empty=False,
                    forbidden_characters=None,
                ),
                fixture.error(
                    reports.codes.INVALID_OPTION_VALUE,
                    option_value="",
                    option_name="hash",
                    allowed_values=(
                        "md5",
                        "sha1",
                        "sha256",
                        "sha384",
                        "sha512",
                    ),
                    cannot_be_empty=False,
                    forbidden_characters=None,
                ),
            ],
        )

    def test_crypto_enabled_cipher_default_hash(self):
        assert_report_item_list_equal(
            self.call_function(
                {},
                {},
                {
                    "cipher": "aes256",
                },
            ),
            [],
        )

    def test_crypto_config_enabled_set_to_disabled(self):
        assert_report_item_list_equal(
            self.call_function({}, {}, {"cipher": "none", "hash": "none"}),
            [
                fixture.error(
                    reports.codes.INVALID_OPTION_VALUE,
                    option_value="none",
                    option_name="cipher",
                    allowed_values=("aes256", "aes192", "aes128"),
                    cannot_be_empty=False,
                    forbidden_characters=None,
                ),
                fixture.error(
                    reports.codes.INVALID_OPTION_VALUE,
                    option_value="none",
                    option_name="hash",
                    allowed_values=(
                        "md5",
                        "sha1",
                        "sha256",
                        "sha384",
                        "sha512",
                    ),
                    cannot_be_empty=False,
                    forbidden_characters=None,
                ),
            ],
        )

    def test_crypto_config_enabled_set_to_default(self):
        assert_report_item_list_equal(
            self.call_function({}, {}, {"cipher": "", "hash": ""}),
            [
                fixture.error(
                    reports.codes.INVALID_OPTION_VALUE,
                    option_value="",
                    option_name="cipher",
                    allowed_values=("aes256", "aes192", "aes128"),
                    cannot_be_empty=False,
                    forbidden_characters=None,
                ),
                fixture.error(
                    reports.codes.INVALID_OPTION_VALUE,
                    option_value="",
                    option_name="hash",
                    allowed_values=(
                        "md5",
                        "sha1",
                        "sha256",
                        "sha384",
                        "sha512",
                    ),
                    cannot_be_empty=False,
                    forbidden_characters=None,
                ),
            ],
        )

    def test_crypto_config_enabled_default_hash(self):
        assert_report_item_list_equal(
            self.call_function({}, {}, {"hash": ""}),
            [
                fixture.error(
                    reports.codes.INVALID_OPTION_VALUE,
                    option_value="",
                    option_name="hash",
                    allowed_values=(
                        "md5",
                        "sha1",
                        "sha256",
                        "sha384",
                        "sha512",
                    ),
                    cannot_be_empty=False,
                    forbidden_characters=None,
                ),
            ],
        )

    def test_crypto_config_enabled_disabled_hash(self):
        assert_report_item_list_equal(
            self.call_function({}, {}, {"hash": "none"}),
            [
                fixture.error(
                    reports.codes.INVALID_OPTION_VALUE,
                    option_value="none",
                    option_name="hash",
                    allowed_values=(
                        "md5",
                        "sha1",
                        "sha256",
                        "sha384",
                        "sha512",
                    ),
                    cannot_be_empty=False,
                    forbidden_characters=None,
                ),
            ],
        )

    def test_crypto_config_enabled_changed_hash(self):
        assert_report_item_list_equal(
            self.call_function({}, {}, {"hash": "md5"}),
            [],
        )

    def test_crypto_config_enabled_changed_cipher(self):
        assert_report_item_list_equal(
            self.call_function({}, {}, {"cipher": "aes128"}),
            [],
        )

    def test_crypto_config_hash_enabled_enable_cipher(self):
        assert_report_item_list_equal(
            self.call_function({}, {}, {"cipher": "aes128"}), []
        )

    def test_crypto_config_hash_enabled_enable_cipher_disable_hash(self):
        assert_report_item_list_equal(
            self.call_function(
                {},
                {},
                {"cipher": "aes128", "hash": "none"},
            ),
            [
                fixture.error(
                    reports.codes.INVALID_OPTION_VALUE,
                    option_value="none",
                    option_name="hash",
                    allowed_values=(
                        "md5",
                        "sha1",
                        "sha256",
                        "sha384",
                        "sha512",
                    ),
                    cannot_be_empty=False,
                    forbidden_characters=None,
                ),
            ],
        )

    def test_crypto_config_hash_enabled_enable_cipher_default_hash(self):
        assert_report_item_list_equal(
            self.call_function(
                {},
                {},
                {"cipher": "aes128", "hash": ""},
            ),
            [
                fixture.error(
                    reports.codes.INVALID_OPTION_VALUE,
                    option_value="",
                    option_name="hash",
                    allowed_values=(
                        "md5",
                        "sha1",
                        "sha256",
                        "sha384",
                        "sha512",
                    ),
                    cannot_be_empty=False,
                    forbidden_characters=None,
                ),
            ],
        )


class UpdateTransportUdp(TransportUdpBase, TestCase):
    def call_function(
        self, generic_options, compression_options, crypto_options
    ):
        return config_validators.update_transport_udp(
            generic_options, compression_options, crypto_options
        )

    def test_empty_values_allowed(self):
        assert_report_item_list_equal(
            self.call_function({"ip_version": "", "netmtu": ""}, {}, {}),
            [],
        )
