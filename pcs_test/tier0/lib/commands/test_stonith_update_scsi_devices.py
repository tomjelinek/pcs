import json
from unittest import mock, TestCase


from pcs_test.tools import fixture
from pcs_test.tools.command_env import get_env_tools
from pcs_test.tools.misc import get_test_resource as rc

from pcs import settings
from pcs.lib.commands import stonith
from pcs.lib.pacemaker.values import timeout_to_milliseconds as to_ms
from pcs.common import (
    communication,
    reports,
)
from pcs.common.interface import dto

from .cluster.common import (
    corosync_conf_fixture,
    get_two_node,
    node_fixture,
)

SCSI_STONITH_ID = "scsi-fence-device"
SCSI_NODE = "node1"
_DIGEST = "0" * 31
DEFAULT_DIGEST = _DIGEST + "0"
ALL_DIGEST = _DIGEST + "1"
NONPRIVATE_DIGEST = _DIGEST + "2"
NONRELOADABLE_DIGEST = _DIGEST + "3"
DEVICES_1 = ("/dev/sda",)
DEVICES_2 = ("/dev/sda", "/dev/sdb")
DEVICES_3 = ("/dev/sda", "/dev/sdb", "/dev/sdc")

DEFAULT_MONITOR = ("monitor", "60s", None, None)
DEFAULT_OPS = (DEFAULT_MONITOR,)
DEFAULT_LRM_START_OPS = (("0", DEFAULT_DIGEST, None, None),)
DEFAULT_LRM_MONITOR_OPS = (("60000", DEFAULT_DIGEST, None, None),)
DEFAULT_LRM_START_OPS_UPDATED = (("0", ALL_DIGEST, None, None),)
DEFAULT_LRM_MONITOR_OPS_UPDATED = (("60000", ALL_DIGEST, None, None),)


def _fixture_ops(resource_id, ops):
    return "\n".join(
        [
            (
                '<op id="{resource_id}-{name}-interval-{_interval}"'
                ' interval="{interval}" {timeout} name="{name}"/>'
            ).format(
                resource_id=resource_id,
                name=name,
                _interval=_interval if _interval else interval,
                interval=interval,
                timeout=f'timeout="{timeout}"' if timeout else "",
            )
            for name, interval, timeout, _interval in ops
        ]
    )


def _fixture_devices_nvpair(resource_id, devices):
    if devices is None:
        return ""
    return (
        '<nvpair id="{resource_id}-instance_attributes-devices" name="devices"'
        ' value="{devices}"/>'
    ).format(resource_id=resource_id, devices=",".join(sorted(devices)))


def fixture_scsi(
    stonith_id=SCSI_STONITH_ID, devices=DEVICES_1, resource_ops=DEFAULT_OPS
):
    return """
        <resources>
            <primitive class="stonith" id="{stonith_id}" type="fence_scsi">
                <instance_attributes id="{stonith_id}-instance_attributes">
                    {devices}
                    <nvpair id="{stonith_id}-instance_attributes-pcmk_host_check" name="pcmk_host_check" value="static-list"/>
                    <nvpair id="{stonith_id}-instance_attributes-pcmk_host_list" name="pcmk_host_list" value="node1 node2 node3"/>
                    <nvpair id="{stonith_id}-instance_attributes-pcmk_reboot_action" name="pcmk_reboot_action" value="off"/>
                </instance_attributes>
                <meta_attributes id="{stonith_id}-meta_attributes">
                    <nvpair id="{stonith_id}-meta_attributes-provides" name="provides" value="unfencing"/>
                </meta_attributes>
                <operations>
                    {operations}
                </operations>
            </primitive>
            <primitive class="ocf" id="dummy" provider="pacemaker" type="Dummy"/>
        </resources>
    """.format(
        stonith_id=stonith_id,
        devices=_fixture_devices_nvpair(stonith_id, devices),
        operations=_fixture_ops(stonith_id, resource_ops),
    )


def _fixture_lrm_rsc_ops(op_type, resource_id, lrm_ops):
    return [
        (
            '<lrm_rsc_op id="{resource_id}_{op_type_id}_{ms}" operation="{op_type}" '
            'interval="{ms}" {_all} {secure} {restart}/>'
        ).format(
            op_type_id="last" if op_type == "start" else op_type,
            op_type=op_type,
            resource_id=resource_id,
            ms=ms,
            _all=f'op-digest="{_all}"' if _all else "",
            secure=f'op-secure-digest="{secure}"' if secure else "",
            restart=f'op-restart-digest="{restart}"' if restart else "",
        )
        for ms, _all, secure, restart in lrm_ops
    ]


def _fixture_lrm_rsc_monitor_ops(resource_id, lrm_monitor_ops):
    return _fixture_lrm_rsc_ops("monitor", resource_id, lrm_monitor_ops)


def _fixture_lrm_rsc_start_ops(resource_id, lrm_start_ops):
    return _fixture_lrm_rsc_ops("start", resource_id, lrm_start_ops)


def _fixture_status_lrm_ops_base(
    resource_id,
    lrm_ops,
):
    return f"""
        <status>
            <node_state id="1" uname="node1">
                <lrm id="1">
                    <lrm_resources>
                        <lrm_resource id="{resource_id}" type="fence_scsi" class="stonith">
                            {lrm_ops}
                        </lrm_resource>
                    </lrm_resources>
                </lrm>
            </node_state>
        </status>
    """


def _fixture_status_lrm_ops(
    resource_id,
    lrm_start_ops=DEFAULT_LRM_START_OPS,
    lrm_monitor_ops=DEFAULT_LRM_MONITOR_OPS,
):
    return _fixture_status_lrm_ops_base(
        resource_id,
        "\n".join(
            _fixture_lrm_rsc_start_ops(resource_id, lrm_start_ops)
            + _fixture_lrm_rsc_monitor_ops(resource_id, lrm_monitor_ops)
        ),
    )


def fixture_digests_xml(resource_id, node_name, devices=""):
    return f"""
        <pacemaker-result api-version="2.9" request="crm_resource --digests --resource {resource_id} --node {node_name} --output-as xml devices={devices}">
            <digests resource="{resource_id}" node="{node_name}" task="stop" interval="0ms">
                <digest type="all" hash="{ALL_DIGEST}">
                    <parameters devices="{devices}" pcmk_host_check="static-list" pcmk_host_list="node1 node2 node3" pcmk_reboot_action="off"/>
                </digest>
                <digest type="nonprivate" hash="{NONPRIVATE_DIGEST}">
                    <parameters devices="{devices}"/>
                </digest>
            </digests>
            <status code="0" message="OK"/>
        </pacemaker-result>
    """


FIXTURE_CRM_MON_RES_RUNNING_1 = f""" <resources> <resource id="{SCSI_STONITH_ID}" resource_agent="stonith:fence_scsi" role="Started" nodes_running_on="1">
            <node name="{SCSI_NODE}" id="1" cached="true"/>
        </resource>
    </resources>
"""

FIXTURE_CRM_MON_RES_RUNNING_2 = f"""
    <resources>
        <resource id="{SCSI_STONITH_ID}" resource_agent="stonith:fence_scsi" role="Started" nodes_running_on="1">
            <node name="node1" id="1" cached="true"/>
            <node name="node2" id="2" cached="true"/>
        </resource>
    </resources>
"""
FIXTURE_CRM_MON_NODES = """
    <nodes>
        <node name="node1" id="1" is_dc="true" resources_running="1"/>
        <node name="node2" id="2"/>
        <node name="node3" id="3"/>
    </nodes>
"""

FIXTURE_CRM_MON_RES_STOPPED = f"""
    <resource id="{SCSI_STONITH_ID}" resource_agent="stonith:fence_scsi" role="Stopped" nodes_running_on="0"/>
"""


@mock.patch.object(
    settings,
    "pacemaker_api_result_schema",
    rc("pcmk_api_rng/api-result.rng"),
)
class UpdateScsiDevices(TestCase):
    def setUp(self):
        self.env_assist, self.config = get_env_tools(self)

        self.existing_nodes = ["node1", "node2", "node3"]
        self.existing_corosync_nodes = [
            node_fixture(node, node_id)
            for node_id, node in enumerate(self.existing_nodes, 1)
        ]
        self.config.env.set_known_nodes(self.existing_nodes)

    def assert_command_success(
        self,
        devices_before=DEVICES_1,
        devices_updated=DEVICES_2,
        resource_ops=DEFAULT_OPS,
        lrm_monitor_ops=DEFAULT_LRM_MONITOR_OPS,
        lrm_start_ops=DEFAULT_LRM_START_OPS,
        lrm_monitor_ops_updated=DEFAULT_LRM_MONITOR_OPS_UPDATED,
        lrm_start_ops_updated=DEFAULT_LRM_START_OPS_UPDATED,
    ):
        # pylint: disable=too-many-locals
        self.config.runner.pcmk.is_resource_digests_supported()
        self.config.runner.cib.load(
            resources=fixture_scsi(
                devices=devices_before, resource_ops=resource_ops
            ),
            status=_fixture_status_lrm_ops(
                SCSI_STONITH_ID,
                lrm_start_ops=lrm_start_ops,
                lrm_monitor_ops=lrm_monitor_ops,
            ),
        )
        self.config.runner.pcmk.load_state(
            resources=FIXTURE_CRM_MON_RES_RUNNING_1, nodes=FIXTURE_CRM_MON_NODES
        )
        devices_opt = "devices={}".format(",".join(devices_updated))
        self.config.runner.pcmk.resource_digests(
            SCSI_STONITH_ID,
            SCSI_NODE,
            name="start.op.digests",
            stdout=fixture_digests_xml(
                SCSI_STONITH_ID, SCSI_NODE, devices=",".join(devices_updated)
            ),
            args=[devices_opt],
        )

        for num, op in enumerate(resource_ops, 1):
            name, interval, timeout, _ = op
            if name != "monitor":
                continue
            args = [devices_opt]
            args.append("CRM_meta_interval={}".format(to_ms(interval)))
            if timeout:
                args.append("CRM_meta_timeout={}".format(to_ms(timeout)))
            self.config.runner.pcmk.resource_digests(
                SCSI_STONITH_ID,
                SCSI_NODE,
                name=f"{name}-{num}.op.digests",
                stdout=fixture_digests_xml(
                    SCSI_STONITH_ID,
                    SCSI_NODE,
                    devices=",".join(devices_updated),
                ),
                args=args,
            )
        self.config.corosync_conf.load_content(
            corosync_conf_fixture(
                self.existing_corosync_nodes,
                get_two_node(len(self.existing_corosync_nodes)),
            )
        )
        self.config.http.scsi.unfence_node(
            devices_updated, node_labels=self.existing_nodes
        )
        self.config.env.push_cib(
            resources=fixture_scsi(
                devices=devices_updated, resource_ops=resource_ops
            ),
            status=_fixture_status_lrm_ops(
                SCSI_STONITH_ID,
                lrm_start_ops=lrm_start_ops_updated,
                lrm_monitor_ops=lrm_monitor_ops_updated,
            ),
        )
        stonith.update_scsi_devices(
            self.env_assist.get_env(), SCSI_STONITH_ID, devices_updated
        )
        self.env_assist.assert_reports([])

    def test_update_1_to_1_devices(self):
        self.assert_command_success(
            devices_before=DEVICES_1, devices_updated=DEVICES_1
        )

    def test_update_2_to_2_devices(self):
        self.assert_command_success(
            devices_before=DEVICES_1, devices_updated=DEVICES_1
        )

    def test_update_1_to_2_devices(self):
        self.assert_command_success()

    def test_update_1_to_3_devices(self):
        self.assert_command_success(
            devices_before=DEVICES_1, devices_updated=DEVICES_3
        )

    def test_update_3_to_1_devices(self):
        self.assert_command_success(
            devices_before=DEVICES_3, devices_updated=DEVICES_1
        )

    def test_update_3_to_2_devices(self):
        self.assert_command_success(
            devices_before=DEVICES_3, devices_updated=DEVICES_2
        )

    def test_default_monitor(self):
        self.assert_command_success()

    def test_no_monitor_ops(self):
        self.assert_command_success(
            resource_ops=(), lrm_monitor_ops=(), lrm_monitor_ops_updated=()
        )

    def test_1_monitor_with_timeout(self):
        self.assert_command_success(
            resource_ops=(("monitor", "30s", "10s", None),),
            lrm_monitor_ops=(("30000", DEFAULT_DIGEST, None, None),),
            lrm_monitor_ops_updated=(("30000", ALL_DIGEST, None, None),),
        )

    def test_2_monitor_ops_with_timeouts(self):
        self.assert_command_success(
            resource_ops=(
                ("monitor", "30s", "10s", None),
                ("monitor", "40s", "20s", None),
            ),
            lrm_monitor_ops=(
                ("30000", DEFAULT_DIGEST, None, None),
                ("40000", DEFAULT_DIGEST, None, None),
            ),
            lrm_monitor_ops_updated=(
                ("30000", ALL_DIGEST, None, None),
                ("40000", ALL_DIGEST, None, None),
            ),
        )

    def test_2_monitor_ops_with_one_timeout(self):
        self.assert_command_success(
            resource_ops=(
                ("monitor", "30s", "10s", None),
                ("monitor", "60s", None, None),
            ),
            lrm_monitor_ops=(
                ("30000", DEFAULT_DIGEST, None, None),
                ("60000", DEFAULT_DIGEST, None, None),
            ),
            lrm_monitor_ops_updated=(
                ("30000", ALL_DIGEST, None, None),
                ("60000", ALL_DIGEST, None, None),
            ),
        )

    def test_various_start_ops_one_lrm_start_op(self):
        self.assert_command_success(
            resource_ops=(
                ("monitor", "60s", None, None),
                ("start", "0s", "40s", None),
                ("start", "0s", "30s", "1"),
                ("start", "10s", "5s", None),
                ("start", "20s", None, None),
            ),
        )

    def test_1_nonrecurring_start_op_with_timeout(self):
        self.assert_command_success(
            resource_ops=(
                ("monitor", "60s", None, None),
                ("start", "0s", "40s", None),
            ),
        )


@mock.patch.object(
    settings,
    "pacemaker_api_result_schema",
    rc("pcmk_api_rng/api-result.rng"),
)
class TestUpdateScsiDevicesFailures(TestCase):
    def setUp(self):
        self.env_assist, self.config = get_env_tools(self)

        self.existing_nodes = ["node1", "node2", "node3"]
        self.existing_corosync_nodes = [
            node_fixture(node, node_id)
            for node_id, node in enumerate(self.existing_nodes, 1)
        ]
        self.config.env.set_known_nodes(self.existing_nodes)

    def test_pcmk_doesnt_support_digests(self):
        self.config.runner.pcmk.is_resource_digests_supported(
            is_supported=False
        )
        self.env_assist.assert_raise_library_error(
            lambda: stonith.update_scsi_devices(
                self.env_assist.get_env(), SCSI_STONITH_ID, ()
            ),
            [
                fixture.error(
                    reports.codes.STONITH_RESTARTLESS_UPDATE_OF_SCSI_DEVICES_NOT_SUPPORTED,
                )
            ],
            expected_in_processor=False,
        )

    def test_devices_cannot_be_empty(self):
        self.config.runner.pcmk.is_resource_digests_supported()
        self.config.runner.cib.load(resources=fixture_scsi())
        self.env_assist.assert_raise_library_error(
            lambda: stonith.update_scsi_devices(
                self.env_assist.get_env(), SCSI_STONITH_ID, ()
            )
        )
        self.env_assist.assert_reports(
            [
                fixture.error(
                    reports.codes.INVALID_OPTION_VALUE,
                    option_name="devices",
                    option_value="",
                    allowed_values=None,
                    cannot_be_empty=True,
                    forbidden_characters=None,
                )
            ]
        )

    def test_nonexistant_id(self):
        self.config.runner.pcmk.is_resource_digests_supported()
        self.config.runner.cib.load(resources=fixture_scsi())
        self.env_assist.assert_raise_library_error(
            lambda: stonith.update_scsi_devices(
                self.env_assist.get_env(), "non-existent-id", DEVICES_2
            )
        )
        self.env_assist.assert_reports(
            [
                fixture.error(
                    reports.codes.ID_NOT_FOUND,
                    id="non-existent-id",
                    expected_types=["primitive"],
                    context_type="cib",
                    context_id="",
                )
            ]
        )

    def test_not_a_resource_id(self):
        self.config.runner.pcmk.is_resource_digests_supported()
        self.config.runner.cib.load(resources=fixture_scsi())
        self.env_assist.assert_raise_library_error(
            lambda: stonith.update_scsi_devices(
                self.env_assist.get_env(),
                f"{SCSI_STONITH_ID}-instance_attributes-devices",
                DEVICES_2,
            )
        )
        self.env_assist.assert_reports(
            [
                fixture.error(
                    reports.codes.ID_BELONGS_TO_UNEXPECTED_TYPE,
                    id=f"{SCSI_STONITH_ID}-instance_attributes-devices",
                    expected_types=["primitive"],
                    current_type="nvpair",
                )
            ]
        )

    def test_not_supported_resource_type(self):
        self.config.runner.pcmk.is_resource_digests_supported()
        self.config.runner.cib.load(resources=fixture_scsi())
        self.env_assist.assert_raise_library_error(
            lambda: stonith.update_scsi_devices(
                self.env_assist.get_env(), "dummy", DEVICES_2
            )
        )
        self.env_assist.assert_reports(
            [
                fixture.error(
                    reports.codes.STONITH_RESOURCE_TYPE_NOT_SUPPORTED_FOR_UPDATE,
                    resource_id="dummy",
                    supported_stonith_types=["fence_scsi"],
                )
            ]
        )

    def test_devices_option_missing(self):
        self.config.runner.pcmk.is_resource_digests_supported()
        self.config.runner.cib.load(resources=fixture_scsi(devices=None))
        self.env_assist.assert_raise_library_error(
            lambda: stonith.update_scsi_devices(
                self.env_assist.get_env(), SCSI_STONITH_ID, DEVICES_2
            )
        )
        self.env_assist.assert_reports(
            [
                fixture.error(
                    reports.codes.STONITH_UNABLE_TO_UPDATE_SCSI_DEVICES,
                    reason=(
                        "no devices option configured for stonith device "
                        f"'{SCSI_STONITH_ID}'"
                    ),
                    reason_type=reports.const.STONITH_UNABLE_TO_UPDATE_SCSI_DEVICES_REASON_OTHER,
                )
            ]
        )

    def test_devices_option_empty(self):
        self.config.runner.pcmk.is_resource_digests_supported()
        self.config.runner.cib.load(resources=fixture_scsi(devices=""))
        self.env_assist.assert_raise_library_error(
            lambda: stonith.update_scsi_devices(
                self.env_assist.get_env(), SCSI_STONITH_ID, DEVICES_2
            )
        )
        self.env_assist.assert_reports(
            [
                fixture.error(
                    reports.codes.STONITH_UNABLE_TO_UPDATE_SCSI_DEVICES,
                    reason=(
                        "no devices option configured for stonith device "
                        f"'{SCSI_STONITH_ID}'"
                    ),
                    reason_type=reports.const.STONITH_UNABLE_TO_UPDATE_SCSI_DEVICES_REASON_OTHER,
                )
            ]
        )

    def test_stonith_resource_is_not_running(self):
        self.config.runner.pcmk.is_resource_digests_supported()
        self.config.runner.cib.load(resources=fixture_scsi())
        self.config.runner.pcmk.load_state(
            resources=FIXTURE_CRM_MON_RES_STOPPED, nodes=FIXTURE_CRM_MON_NODES
        )
        self.env_assist.assert_raise_library_error(
            lambda: stonith.update_scsi_devices(
                self.env_assist.get_env(), SCSI_STONITH_ID, DEVICES_2
            ),
            [
                fixture.error(
                    reports.codes.STONITH_UNABLE_TO_UPDATE_SCSI_DEVICES,
                    reason=f"resource '{SCSI_STONITH_ID}' is not running on any node",
                    reason_type=reports.const.STONITH_UNABLE_TO_UPDATE_SCSI_DEVICES_REASON_NOT_RUNNING,
                )
            ],
            expected_in_processor=False,
        )

    def test_stonith_resource_is_running_on_more_than_one_node(self):
        self.config.runner.pcmk.is_resource_digests_supported()
        self.config.runner.cib.load(resources=fixture_scsi())
        self.config.runner.pcmk.load_state(
            resources=FIXTURE_CRM_MON_RES_RUNNING_2, nodes=FIXTURE_CRM_MON_NODES
        )
        self.env_assist.assert_raise_library_error(
            lambda: stonith.update_scsi_devices(
                self.env_assist.get_env(), SCSI_STONITH_ID, DEVICES_2
            ),
            [
                fixture.error(
                    reports.codes.STONITH_UNABLE_TO_UPDATE_SCSI_DEVICES,
                    reason=(
                        f"resource '{SCSI_STONITH_ID}' is running on more than "
                        "1 node"
                    ),
                    reason_type=reports.const.STONITH_UNABLE_TO_UPDATE_SCSI_DEVICES_REASON_OTHER,
                )
            ],
            expected_in_processor=False,
        )

    def test_lrm_op_missing_digest_attributes(self):
        devices = ",".join(DEVICES_2)
        self.config.runner.pcmk.is_resource_digests_supported()
        self.config.runner.cib.load(
            resources=fixture_scsi(),
            status=_fixture_status_lrm_ops_base(
                SCSI_STONITH_ID,
                f'<lrm_rsc_op id="{SCSI_STONITH_ID}_last" operation="start"/>',
            ),
        )
        self.config.runner.pcmk.load_state(
            resources=FIXTURE_CRM_MON_RES_RUNNING_1, nodes=FIXTURE_CRM_MON_NODES
        )
        self.config.runner.pcmk.resource_digests(
            SCSI_STONITH_ID,
            SCSI_NODE,
            name="start.op.digests",
            stdout=fixture_digests_xml(
                SCSI_STONITH_ID,
                SCSI_NODE,
                devices=devices,
            ),
            args=[f"devices={devices}"],
        )
        self.env_assist.assert_raise_library_error(
            lambda: stonith.update_scsi_devices(
                self.env_assist.get_env(), SCSI_STONITH_ID, DEVICES_2
            ),
            [
                fixture.error(
                    reports.codes.STONITH_UNABLE_TO_UPDATE_SCSI_DEVICES,
                    reason="no digests attributes in lrm_rsc_op element",
                    reason_type=reports.const.STONITH_UNABLE_TO_UPDATE_SCSI_DEVICES_REASON_OTHER,
                )
            ],
            expected_in_processor=False,
        )

    def test_crm_resource_digests_missing(self):
        devices = ",".join(DEVICES_2)
        self.config.runner.pcmk.is_resource_digests_supported()
        self.config.runner.cib.load(
            resources=fixture_scsi(),
            status=_fixture_status_lrm_ops_base(
                SCSI_STONITH_ID,
                (
                    f'<lrm_rsc_op id="{SCSI_STONITH_ID}_last" '
                    'operation="start" op-restart-digest="somedigest" />'
                ),
            ),
        )
        self.config.runner.pcmk.load_state(
            resources=FIXTURE_CRM_MON_RES_RUNNING_1, nodes=FIXTURE_CRM_MON_NODES
        )
        self.config.runner.pcmk.resource_digests(
            SCSI_STONITH_ID,
            SCSI_NODE,
            name="start.op.digests",
            stdout=fixture_digests_xml(
                SCSI_STONITH_ID,
                SCSI_NODE,
                devices=devices,
            ),
            args=[f"devices={devices}"],
        )
        self.env_assist.assert_raise_library_error(
            lambda: stonith.update_scsi_devices(
                self.env_assist.get_env(), SCSI_STONITH_ID, DEVICES_2
            ),
            [
                fixture.error(
                    reports.codes.STONITH_UNABLE_TO_UPDATE_SCSI_DEVICES,
                    reason=(
                        "necessary digest for 'op-restart-digest' attribute is "
                        "missing"
                    ),
                    reason_type=reports.const.STONITH_UNABLE_TO_UPDATE_SCSI_DEVICES_REASON_OTHER,
                )
            ],
            expected_in_processor=False,
        )

    def test_no_lrm_start_op(self):
        self.config.runner.pcmk.is_resource_digests_supported()
        self.config.runner.cib.load(
            resources=fixture_scsi(),
            status=_fixture_status_lrm_ops(SCSI_STONITH_ID, lrm_start_ops=()),
        )
        self.config.runner.pcmk.load_state(
            resources=FIXTURE_CRM_MON_RES_RUNNING_1, nodes=FIXTURE_CRM_MON_NODES
        )
        self.env_assist.assert_raise_library_error(
            lambda: stonith.update_scsi_devices(
                self.env_assist.get_env(), SCSI_STONITH_ID, DEVICES_2
            ),
            [
                fixture.error(
                    reports.codes.STONITH_UNABLE_TO_UPDATE_SCSI_DEVICES,
                    reason=(
                        "lrm_rsc_op element for start operation was not found"
                    ),
                    reason_type=reports.const.STONITH_UNABLE_TO_UPDATE_SCSI_DEVICES_REASON_OTHER,
                )
            ],
            expected_in_processor=False,
        )

    def test_monitor_ops_and_lrm_monitor_ops_do_not_match(self):
        self.config.runner.pcmk.is_resource_digests_supported()
        self.config.runner.cib.load(
            resources=fixture_scsi(
                resource_ops=(
                    ("monitor", "30s", "10s", None),
                    ("monitor", "30s", "20s", "31"),
                    ("monitor", "60s", None, None),
                )
            ),
            status=_fixture_status_lrm_ops(SCSI_STONITH_ID),
        )
        self.config.runner.pcmk.load_state(
            resources=FIXTURE_CRM_MON_RES_RUNNING_1, nodes=FIXTURE_CRM_MON_NODES
        )
        self.config.runner.pcmk.resource_digests(
            SCSI_STONITH_ID,
            SCSI_NODE,
            name="start.op.digests",
            stdout=fixture_digests_xml(
                SCSI_STONITH_ID, SCSI_NODE, devices=",".join(DEVICES_2)
            ),
            args=["devices={}".format(",".join(DEVICES_2))],
        )
        self.env_assist.assert_raise_library_error(
            lambda: stonith.update_scsi_devices(
                self.env_assist.get_env(), SCSI_STONITH_ID, DEVICES_2
            ),
            [
                fixture.error(
                    reports.codes.STONITH_UNABLE_TO_UPDATE_SCSI_DEVICES,
                    reason=(
                        "number of lrm_rsc_op and op elements for monitor "
                        "operation differs"
                    ),
                    reason_type=reports.const.STONITH_UNABLE_TO_UPDATE_SCSI_DEVICES_REASON_OTHER,
                )
            ],
            expected_in_processor=False,
        )

    def test_lrm_monitor_ops_not_found(self):
        self.config.runner.pcmk.is_resource_digests_supported()
        self.config.runner.cib.load(
            resources=fixture_scsi(
                resource_ops=(("monitor", "30s", None, None),)
            ),
            status=_fixture_status_lrm_ops(SCSI_STONITH_ID),
        )
        self.config.runner.pcmk.load_state(
            resources=FIXTURE_CRM_MON_RES_RUNNING_1, nodes=FIXTURE_CRM_MON_NODES
        )
        self.config.runner.pcmk.resource_digests(
            SCSI_STONITH_ID,
            SCSI_NODE,
            name="start.op.digests",
            stdout=fixture_digests_xml(
                SCSI_STONITH_ID, SCSI_NODE, devices=",".join(DEVICES_2)
            ),
            args=["devices={}".format(",".join(DEVICES_2))],
        )
        self.env_assist.assert_raise_library_error(
            lambda: stonith.update_scsi_devices(
                self.env_assist.get_env(), SCSI_STONITH_ID, DEVICES_2
            ),
            [
                fixture.error(
                    reports.codes.STONITH_UNABLE_TO_UPDATE_SCSI_DEVICES,
                    reason=(
                        "monitor lrm_rsc_op element for resource "
                        f"'{SCSI_STONITH_ID}', node '{SCSI_NODE}' and interval "
                        "'30000' not found"
                    ),
                    reason_type=reports.const.STONITH_UNABLE_TO_UPDATE_SCSI_DEVICES_REASON_OTHER,
                )
            ],
            expected_in_processor=False,
        )

    def test_node_missing_name_and_missing_auth_token(self):
        self.config.runner.pcmk.is_resource_digests_supported()
        self.config.runner.cib.load(
            resources=fixture_scsi(),
            status=_fixture_status_lrm_ops(SCSI_STONITH_ID),
        )
        self.config.runner.pcmk.load_state(
            resources=FIXTURE_CRM_MON_RES_RUNNING_1, nodes=FIXTURE_CRM_MON_NODES
        )
        self.config.runner.pcmk.resource_digests(
            SCSI_STONITH_ID,
            SCSI_NODE,
            name="start.op.digests",
            stdout=fixture_digests_xml(
                SCSI_STONITH_ID, SCSI_NODE, devices=",".join(DEVICES_2)
            ),
            args=["devices={}".format(",".join(DEVICES_2))],
        )
        self.config.runner.pcmk.resource_digests(
            SCSI_STONITH_ID,
            SCSI_NODE,
            name="monitor.op.digests",
            stdout=fixture_digests_xml(
                SCSI_STONITH_ID, SCSI_NODE, devices=",".join(DEVICES_2)
            ),
            args=[
                "devices={}".format(",".join(DEVICES_2)),
                "CRM_meta_interval=60000",
            ],
        )
        self.config.corosync_conf.load_content(
            corosync_conf_fixture(
                self.existing_corosync_nodes
                + [[("ring0_addr", "custom_node"), ("nodeid", "5")]],
            )
        )
        self.config.env.set_known_nodes(self.existing_nodes[:-1])
        self.env_assist.assert_raise_library_error(
            lambda: stonith.update_scsi_devices(
                self.env_assist.get_env(), SCSI_STONITH_ID, DEVICES_2
            ),
        )
        self.env_assist.assert_reports(
            [
                fixture.error(
                    reports.codes.COROSYNC_CONFIG_MISSING_NAMES_OF_NODES,
                    fatal=True,
                ),
                fixture.error(
                    reports.codes.HOST_NOT_FOUND,
                    host_list=[self.existing_nodes[-1]],
                ),
            ]
        )

    def test_unfence_failure(self):
        devices = ",".join(DEVICES_2)
        self.config.runner.pcmk.is_resource_digests_supported()
        self.config.runner.cib.load(
            resources=fixture_scsi(),
            status=_fixture_status_lrm_ops(SCSI_STONITH_ID),
        )
        self.config.runner.pcmk.load_state(
            resources=FIXTURE_CRM_MON_RES_RUNNING_1, nodes=FIXTURE_CRM_MON_NODES
        )
        self.config.runner.pcmk.resource_digests(
            SCSI_STONITH_ID,
            SCSI_NODE,
            name="start.op.digests",
            stdout=fixture_digests_xml(
                SCSI_STONITH_ID,
                SCSI_NODE,
                devices=devices,
            ),
            args=[f"devices={devices}"],
        )
        self.config.runner.pcmk.resource_digests(
            SCSI_STONITH_ID,
            SCSI_NODE,
            name="monitor.op.digests",
            stdout=fixture_digests_xml(
                SCSI_STONITH_ID,
                SCSI_NODE,
                devices=devices,
            ),
            args=[
                f"devices={devices}",
                "CRM_meta_interval=60000",
            ],
        )
        self.config.corosync_conf.load_content(
            corosync_conf_fixture(self.existing_corosync_nodes)
        )
        self.config.http.scsi.unfence_node(
            devices,
            communication_list=[
                dict(
                    label=self.existing_nodes[0],
                    raw_data=json.dumps(
                        dict(devices=DEVICES_2, node=self.existing_nodes[0])
                    ),
                    was_connected=False,
                    error_msg="errA",
                ),
                dict(
                    label=self.existing_nodes[1],
                    raw_data=json.dumps(
                        dict(devices=DEVICES_2, node=self.existing_nodes[1])
                    ),
                    output=json.dumps(
                        dto.to_dict(
                            communication.dto.InternalCommunicationResultDto(
                                status=communication.const.COM_STATUS_ERROR,
                                status_msg="error",
                                report_list=[
                                    reports.ReportItem.error(
                                        reports.messages.StonithUnfencingFailed(
                                            "errB"
                                        )
                                    ).to_dto()
                                ],
                                data=None,
                            )
                        )
                    ),
                ),
                dict(
                    label=self.existing_nodes[2],
                    raw_data=json.dumps(
                        dict(devices=DEVICES_2, node=self.existing_nodes[2])
                    ),
                ),
            ],
        )
        self.env_assist.assert_raise_library_error(
            lambda: stonith.update_scsi_devices(
                self.env_assist.get_env(), SCSI_STONITH_ID, DEVICES_2
            ),
        )
        self.env_assist.assert_reports(
            [
                fixture.error(
                    reports.codes.NODE_COMMUNICATION_ERROR_UNABLE_TO_CONNECT,
                    node=self.existing_nodes[0],
                    command="api/v1/scsi-unfence-node/v1",
                    reason="errA",
                ),
                fixture.error(
                    reports.codes.STONITH_UNFENCING_FAILED,
                    reason="errB",
                    context=reports.dto.ReportItemContextDto(
                        node=self.existing_nodes[1],
                    ),
                ),
            ]
        )
