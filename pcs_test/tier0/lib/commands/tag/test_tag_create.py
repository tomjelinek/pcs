from unittest import TestCase

from pcs_test.tier0.lib.commands.tag.tag_common import (
    fixture_resources_for_ids,
    fixture_tags_xml,
)
from pcs_test.tools import fixture
from pcs_test.tools.command_env import get_env_tools

from pcs.common import report_codes
from pcs.lib.commands import tag as cmd_tag


TAG1_ID1_ID2 = fixture_tags_xml([("tag1", ("id1", "id2"))])


class TestTagCreate(TestCase):
    def setUp(self):
        self.env_assist, self.config = get_env_tools(self)
        self.config.runner.cib.load(
            filename="cib-empty.xml",
            resources=fixture_resources_for_ids(),
        )

    def test_success_create(self):
        self.config.env.push_cib(append={".//configuration": TAG1_ID1_ID2})
        cmd_tag.create(self.env_assist.get_env(), "tag1", ["id1", "id2"])

    def test_success_create_cib_upgrade(self):
        self.config.runner.cib.load(
            name="load_cib_old_version",
            filename="cib-empty-1.2.xml",
            resources=fixture_resources_for_ids(),
            before="runner.cib.load",
        )
        self.config.runner.cib.upgrade(before="runner.cib.load")
        self.config.env.push_cib(append={".//configuration": TAG1_ID1_ID2})
        cmd_tag.create(self.env_assist.get_env(), "tag1", ["id1", "id2"])
        self.env_assist.assert_reports([
            fixture.info(report_codes.CIB_UPGRADE_SUCCESSFUL),
        ])

    def test_invalid_tag_id(self):
        self.env_assist.assert_raise_library_error(
            lambda: cmd_tag.create(
                self.env_assist.get_env(),
                "#tag",
                ["id1", "id2"],
            )
        )
        self.env_assist.assert_reports([
            fixture.report_invalid_id("#tag", "#"),
        ])

    def test_multiple_errors(self):
        self.env_assist.assert_raise_library_error(
            lambda: cmd_tag.create(
                self.env_assist.get_env(),
                "",
                ["", ""],
            )
        )
        self.env_assist.assert_reports([
            fixture.error(report_codes.EMPTY_ID, id=""),
            fixture.error(report_codes.TAG_CANNOT_CONTAIN_ITSELF),
            *[
                fixture.report_not_found(_id, context_type="resources")
                for _id in ["", ""]
            ],
            fixture.error(
                report_codes.TAG_IDS_DUPLICATION,
                duplicate_ids_list=[""],
            ),
        ])
