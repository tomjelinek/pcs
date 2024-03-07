from textwrap import dedent
from unittest import TestCase

from lxml import etree

from pcs.common import const
from pcs.common.str_tools import format_list

from pcs_test.tools.assertions import AssertPcsMixin
from pcs_test.tools.cib import get_assert_pcs_effect_mixin
from pcs_test.tools.misc import (
    get_test_resource,
    get_tmp_file,
    write_data_to_tmpfile,
)
from pcs_test.tools.pcs_runner import PcsRunner
from pcs_test.tools.xml import XmlManipulation

ERRORS_HAVE_OCCURRED = (
    "Error: Errors have occurred, therefore pcs is unable to continue\n"
)
empty_cib = get_test_resource("cib-empty-3.7.xml")


class RuleBaseMixin(
    get_assert_pcs_effect_mixin(
        lambda cib: etree.tostring(etree.parse(cib).find(".//constraints"))
    ),
    AssertPcsMixin,
):
    xml_resource = """
        <primitive id="R1" class="ocf" provider="pacemaker" type="Dummy" />
    """
    xml_constraint_simple = """
        <rsc_location id="loc-simple" rsc="R1" node="node1" score="7" />
    """
    xml_constraint_rule = """
        <rsc_location id="loc-rule" rsc="R1">
          <rule id="loc-rule-rule" boolean-op="and" score="INFINITY">
            <expression id="loc-rule-rule-expr"
                attribute="#uname" operation="eq" value="node2"
            />
          </rule>
          {second_rule}
        </rsc_location>
    """
    xml_constraint_rule_duplicate = """
        <rsc_location id="loc-rule-dup" rsc="R1">
          <rule id="loc-rule-dup-rule" boolean-op="and" score="INFINITY">
            <expression id="loc-rule-dup-rule-expr"
                attribute="#uname" operation="eq" value="node3"
            />
          </rule>
        </rsc_location>
    """

    def setUp(self):
        self.temp_cib = get_tmp_file("tier1_constraint_location_rule")
        self.pcs_runner = PcsRunner(self.temp_cib.name)

        xml_manip = XmlManipulation.from_file(empty_cib)
        xml_manip.append_to_first_tag_name("resources", self.xml_resource)
        xml_manip.append_to_first_tag_name(
            "constraints",
            self.xml_constraint_simple,
            self.xml_constraint_rule.format(second_rule=""),
            self.xml_constraint_rule_duplicate,
        )
        write_data_to_tmpfile(str(xml_manip), self.temp_cib)

    def tearDown(self):
        self.temp_cib.close()


class CreateWithRule(RuleBaseMixin, TestCase):
    def fixture_constraints(self, additional_xml):
        return (
            "<constraints>"
            + self.xml_constraint_simple
            + self.xml_constraint_rule.format(second_rule="")
            + self.xml_constraint_rule_duplicate
            + additional_xml
            + "</constraints>"
        )

    def test_success_minimal(self):
        self.assert_effect(
            [
                "constraint location R1 rule #uname eq node1".split(),
                "constraint location %R1 rule #uname eq node1".split(),
                "constraint location resource%R1 rule #uname eq node1".split(),
            ],
            self.fixture_constraints(
                """
                <rsc_location id="location-R1" rsc="R1">
                  <rule id="location-R1-rule" boolean-op="and" score="INFINITY">
                    <expression id="location-R1-rule-expr"
                        attribute="#uname" operation="eq" value="node1" />
                  </rule>
                </rsc_location>
                """
            ),
        )

    def test_success_all_options(self):
        self.assert_effect(
            (
                "constraint location regexp%R\\d+ rule id=my-rule score=7 "
                "constraint-id=my-loc resource-discovery=always role=Promoted "
                "#uname eq node1"
            ).split(),
            self.fixture_constraints(
                """
                <rsc_location id="my-loc" rsc-pattern="R\\d+"
                    resource-discovery="always"
                >
                  <rule id="my-rule" boolean-op="and" score="7" role="Promoted">
                    <expression id="my-rule-expr"
                        attribute="#uname" operation="eq" value="node1" />
                  </rule>
                </rsc_location>
                """
            ),
        )

    def test_duplicate_constraint(self):
        self.assert_pcs_fail(
            "constraint location R1 rule #uname eq node2".split(),
            stderr_full=dedent(
                """\
                Duplicate constraints:
                  resource 'R1' (id: loc-rule)
                    Rules:
                      Rule: boolean-op=and score=INFINITY (id: loc-rule-rule)
                        Expression: #uname eq node2 (id: loc-rule-rule-expr)
                Error: Duplicate constraint already exists, use --force to override
                """
                + ERRORS_HAVE_OCCURRED
            ),
        )

    def test_duplicate_constraint_forced(self):
        self.assert_effect(
            "--force constraint location R1 rule #uname eq node2".split(),
            self.fixture_constraints(
                """
                <rsc_location id="location-R1" rsc="R1">
                  <rule id="location-R1-rule" boolean-op="and" score="INFINITY">
                    <expression id="location-R1-rule-expr"
                        attribute="#uname" operation="eq" value="node2" />
                  </rule>
                </rsc_location>
                """
            ),
            stderr_full=dedent(
                """\
                Duplicate constraints:
                  resource 'R1' (id: loc-rule)
                    Rules:
                      Rule: boolean-op=and score=INFINITY (id: loc-rule-rule)
                        Expression: #uname eq node2 (id: loc-rule-rule-expr)
                Warning: Duplicate constraint already exists
                """
            ),
        )

    def test_errors(self):
        roles = format_list(
            const.PCMK_ROLES_PROMOTED + const.PCMK_ROLES_UNPROMOTED
        )
        self.assert_pcs_fail(
            (
                "constraint location R1 rule resource-discovery=badly "
                "role=bad-role bad=option #uname eq"
            ).split(),
            stderr_full=dedent(
                f"""\
                Error: 'badly' is not a valid resource-discovery value, use 'always', 'exclusive', 'never', use --force to override
                Error: 'bad-role' is not a valid role value, use {roles}
                Error: 'bad=option #uname eq' is not a valid rule expression, parse error near or after line 1 column 12
                  bad=option #uname eq
                  -----------^
                """
                + ERRORS_HAVE_OCCURRED
            ),
        )


class RuleAdd(RuleBaseMixin, TestCase):
    def fixture_constraints(self, additional_rule_xml, replace_simple_xml=None):
        return (
            "<constraints>"
            + (replace_simple_xml or self.xml_constraint_simple)
            + self.xml_constraint_rule.format(second_rule=additional_rule_xml)
            + self.xml_constraint_rule_duplicate
            + "</constraints>"
        )

    def test_success_minimal(self):
        self.assert_effect(
            "constraint rule add loc-rule #uname eq node1".split(),
            self.fixture_constraints(
                """
                <rule id="loc-rule-rule-1" boolean-op="and" score="INFINITY">
                  <expression id="loc-rule-rule-1-expr"
                      attribute="#uname" operation="eq" value="node1" />
                </rule>
                """
            ),
        )

    def test_success_all_options(self):
        self.assert_effect(
            (
                "constraint rule add loc-rule id=my-rule score=7 role=Promoted "
                "#uname eq node1"
            ).split(),
            self.fixture_constraints(
                """
                <rule id="my-rule" boolean-op="and" score="7" role="Promoted">
                  <expression id="my-rule-expr"
                      attribute="#uname" operation="eq" value="node1" />
                </rule>
                """
            ),
        )

    def test_duplicate_constraint(self):
        self.assert_pcs_fail(
            "constraint rule add loc-rule #uname eq node3".split(),
            stderr_full=dedent(
                """\
                Duplicate constraints:
                  resource 'R1' (id: loc-rule-dup)
                    Rules:
                      Rule: boolean-op=and score=INFINITY (id: loc-rule-dup-rule)
                        Expression: #uname eq node3 (id: loc-rule-dup-rule-expr)
                Error: Duplicate constraint already exists, use --force to override
                """
                + ERRORS_HAVE_OCCURRED
            ),
        )

    def test_duplicate_constraint_forced(self):
        self.assert_effect(
            "--force constraint rule add loc-rule #uname eq node3".split(),
            self.fixture_constraints(
                """
                <rule id="loc-rule-rule-1" boolean-op="and" score="INFINITY">
                  <expression id="loc-rule-rule-1-expr"
                      attribute="#uname" operation="eq" value="node3" />
                </rule>
                """
            ),
            stderr_full=dedent(
                """\
                Duplicate constraints:
                  resource 'R1' (id: loc-rule-dup)
                    Rules:
                      Rule: boolean-op=and score=INFINITY (id: loc-rule-dup-rule)
                        Expression: #uname eq node3 (id: loc-rule-dup-rule-expr)
                Warning: Duplicate constraint already exists
                """
            ),
        )

    def test_duplicate_rule_in_own_constraint(self):
        self.assert_pcs_fail(
            "constraint rule add loc-rule #uname eq node2".split(),
            stderr_full=dedent(
                """\
                Duplicate constraints:
                  resource 'R1' (id: loc-rule)
                    Rules:
                      Rule: boolean-op=and score=INFINITY (id: loc-rule-rule)
                        Expression: #uname eq node2 (id: loc-rule-rule-expr)
                Error: Duplicate constraint already exists, use --force to override
                """
                + ERRORS_HAVE_OCCURRED
            ),
        )

    def test_duplicate_rule_in_own_constraint_forced(self):
        self.assert_effect(
            "--force constraint rule add loc-rule #uname eq node2".split(),
            self.fixture_constraints(
                """
                <rule id="loc-rule-rule-1" boolean-op="and" score="INFINITY">
                  <expression id="loc-rule-rule-1-expr"
                      attribute="#uname" operation="eq" value="node2" />
                </rule>
                """
            ),
            stderr_full=dedent(
                """\
                Duplicate constraints:
                  resource 'R1' (id: loc-rule)
                    Rules:
                      Rule: boolean-op=and score=INFINITY (id: loc-rule-rule)
                        Expression: #uname eq node2 (id: loc-rule-rule-expr)
                Warning: Duplicate constraint already exists
                """
            ),
        )

    def test_simple_to_rule(self):
        self.assert_effect(
            "constraint rule add loc-simple #uname eq node1".split(),
            self.fixture_constraints(
                "",
                """
                <rsc_location id="loc-simple" rsc="R1">
                  <rule id="loc-simple-rule" boolean-op="and" score="INFINITY">
                    <expression id="loc-simple-rule-expr"
                        attribute="#uname" operation="eq" value="node1" />
                  </rule>
                </rsc_location>
                """,
            ),
        )

    def test_errors(self):
        roles = format_list(
            const.PCMK_ROLES_PROMOTED + const.PCMK_ROLES_UNPROMOTED
        )
        self.assert_pcs_fail(
            "constraint rule add loc-rule role=bad-role bad=option #uname eq".split(),
            stderr_full=dedent(
                f"""\
                Error: 'bad-role' is not a valid role value, use {roles}
                Error: 'bad=option #uname eq' is not a valid rule expression, parse error near or after line 1 column 12
                  bad=option #uname eq
                  -----------^
                """
                + ERRORS_HAVE_OCCURRED
            ),
        )
