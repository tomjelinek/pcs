import os.path
import re
from typing import (
    cast,
    Dict,
    Iterable,
    List,
    Optional,
    Tuple,
)

from lxml import etree
from lxml.etree import _Element

from pcs import settings
from pcs.common import reports
from pcs.common.reports import ReportProcessor
from pcs.common.reports.item import ReportItem
from pcs.common.str_tools import join_multilines
from pcs.common.tools import (
    format_os_error,
    xml_fromstring,
    Version,
)
from pcs.common.types import CibRuleInEffectStatus
from pcs.lib.cib.tools import get_pacemaker_version_by_which_cib_was_validated
from pcs.lib.errors import LibraryError
from pcs.lib.external import CommandRunner
from pcs.lib.pacemaker import api_result
from pcs.lib.pacemaker.state import ClusterState
from pcs.lib.tools import write_tmpfile
from pcs.lib.xml_tools import etree_to_str


__EXITCODE_NOT_CONNECTED = 102
__EXITCODE_CIB_SCOPE_VALID_BUT_NOT_PRESENT = 105
__EXITCODE_WAIT_TIMEOUT = 124
__RESOURCE_REFRESH_OPERATION_COUNT_THRESHOLD = 100


class PacemakerNotConnectedException(LibraryError):
    pass


class FenceHistoryCommandErrorException(Exception):
    pass


### status


def get_cluster_status_dom(runner: CommandRunner) -> _Element:
    def validate_dom(dom, rng):
        try:
            if os.path.isfile(rng):
                etree.RelaxNG(file=rng).assertValid(dom)
            return dom
        except etree.DocumentInvalid as e:
            raise LibraryError(
                ReportItem.error(reports.messages.BadClusterStateFormat())
            ) from e

    def get_dom(xml, rng):
        try:
            return validate_dom(xml_fromstring(xml), rng)
        except etree.XMLSyntaxError as e:
            raise LibraryError(
                ReportItem.error(reports.messages.BadClusterStateFormat())
            ) from e

    pcmk_supports_new_format = _is_in_pcmk_tool_help(
        runner, "crm_mon", "--output-as="
    )
    format_option = (
        ["--output-as", "xml"] if pcmk_supports_new_format else ["--as-xml"]
    )

    stdout, stderr, retval = runner.run(
        [__exec("crm_mon"), "--one-shot", "--inactive"] + format_option
    )

    if retval != 0:
        klass = (
            PacemakerNotConnectedException
            if retval == __EXITCODE_NOT_CONNECTED
            else LibraryError
        )
        if pcmk_supports_new_format:
            # Try to process the output as an XML. If it cannot be parsed, then
            # process it as a plaintext. If it is an XML but it doesn't conform
            # to the schema, raise an error (don't catch etree.DocumentInvalid
            # exception).
            try:
                status = get_status_from_api_result(
                    validate_dom(
                        xml_fromstring(stdout),
                        settings.pacemaker_api_result_schema,
                    )
                )
                message = join_multilines(
                    [status.message] + list(status.errors)
                )
            except etree.XMLSyntaxError:
                message = join_multilines([stderr, stdout])
        else:
            message = join_multilines([stderr, stdout])
        raise klass(ReportItem.error(reports.messages.CrmMonError(message)))

    if pcmk_supports_new_format:
        return get_dom(stdout, settings.pacemaker_api_result_schema)

    dom = get_dom(stdout, settings.crm_mon_schema)
    new_format_dom = etree.Element(
        "pacemaker-result",
        {
            "api-version": "2.3",
            "request": "crm_mon --as-xml",
        },
    )
    for child in dom.getchildren():
        new_format_dom.append(child)
    etree.SubElement(new_format_dom, "status", {"code": "0", "message": "OK"})
    return validate_dom(new_format_dom, settings.pacemaker_api_result_schema)


def get_cluster_status_text(
    runner: CommandRunner,
    hide_inactive_resources: bool,
    verbose: bool,
) -> Tuple[str, List[str]]:
    cmd = [__exec("crm_mon"), "--one-shot"]
    if not hide_inactive_resources:
        cmd.append("--inactive")
    if verbose:
        cmd.extend(["--show-detail", "--show-node-attributes", "--failcounts"])
        # by default, pending and failed actions are displayed
        # with verbose==True, we display the whole history
        if is_fence_history_supported_status(runner):
            cmd.append("--fence-history=3")
    stdout, stderr, retval = runner.run(cmd)

    if retval != 0:
        raise LibraryError(
            ReportItem.error(
                reports.messages.CrmMonError(join_multilines([stderr, stdout]))
            )
        )
    warnings: List[str] = []
    if stderr.strip():
        warnings = [
            line
            for line in stderr.strip().splitlines()
            if verbose or not line.startswith("DEBUG: ")
        ]

    return stdout.strip(), warnings


def get_ticket_status_text(runner: CommandRunner) -> Tuple[str, str, int]:
    stdout, stderr, retval = runner.run([__exec("crm_ticket"), "--details"])
    return stdout.strip(), stderr.strip(), retval


### cib


def get_cib_xml_cmd_results(runner, scope=None):
    command = [__exec("cibadmin"), "--local", "--query"]
    if scope:
        command.append("--scope={0}".format(scope))
    stdout, stderr, returncode = runner.run(command)
    return stdout, stderr, returncode


def get_cib_xml(runner, scope=None):
    stdout, stderr, retval = get_cib_xml_cmd_results(runner, scope)
    if retval != 0:
        if retval == __EXITCODE_CIB_SCOPE_VALID_BUT_NOT_PRESENT and scope:
            raise LibraryError(
                ReportItem.error(
                    reports.messages.CibLoadErrorScopeMissing(
                        scope, join_multilines([stderr, stdout])
                    )
                )
            )
        raise LibraryError(
            ReportItem.error(
                reports.messages.CibLoadError(join_multilines([stderr, stdout]))
            )
        )
    return stdout


def parse_cib_xml(xml):
    return xml_fromstring(xml)


def get_cib(xml):
    try:
        return parse_cib_xml(xml)
    except (etree.XMLSyntaxError, etree.DocumentInvalid) as e:
        raise LibraryError(
            ReportItem.error(reports.messages.CibLoadErrorBadFormat(str(e)))
        ) from e


def verify(runner, verbose=False):
    crm_verify_cmd = [__exec("crm_verify")]
    # Currently, crm_verify can suggest up to two -V options but it accepts
    # more than two. We stick with two -V options if verbose mode was enabled.
    if verbose:
        crm_verify_cmd.extend(["-V", "-V"])
    # With the `crm_verify` command it is not possible simply use the
    # environment variable CIB_file because `crm_verify` simply tries to
    # connect to cib file via tool that can fail because: Update does not
    # conform to the configured schema
    # So we use the explicit flag `--xml-file`.
    cib_tmp_file = runner.env_vars.get("CIB_file", None)
    if cib_tmp_file is None:
        crm_verify_cmd.append("--live-check")
    else:
        crm_verify_cmd.extend(["--xml-file", cib_tmp_file])
    stdout, stderr, returncode = runner.run(crm_verify_cmd)
    can_be_more_verbose = False
    if returncode != 0:
        # remove lines with -V options
        rx_v_option = re.compile(r".*-V( -V)* .*more detail.*")
        new_lines = []
        for line in stderr.splitlines(keepends=True):
            if rx_v_option.match(line):
                can_be_more_verbose = True
                continue
            new_lines.append(line)
        # pcs has only one verbose option and cannot be more verbose like
        # `crm_verify` with more -V options. Decision has been made that pcs is
        # limited to only two -V opions.
        if verbose:
            can_be_more_verbose = False
        stderr = "".join(new_lines)
    return stdout, stderr, returncode, can_be_more_verbose


def replace_cib_configuration_xml(runner, xml):
    cmd = [
        __exec("cibadmin"),
        "--replace",
        "--verbose",
        "--xml-pipe",
        "--scope",
        "configuration",
    ]
    stdout, stderr, retval = runner.run(cmd, stdin_string=xml)
    if retval != 0:
        raise LibraryError(
            ReportItem.error(reports.messages.CibPushError(stderr, stdout))
        )


def replace_cib_configuration(runner, tree):
    return replace_cib_configuration_xml(runner, etree_to_str(tree))


def push_cib_diff_xml(runner, cib_diff_xml):
    cmd = [
        __exec("cibadmin"),
        "--patch",
        "--verbose",
        "--xml-pipe",
    ]
    stdout, stderr, retval = runner.run(cmd, stdin_string=cib_diff_xml)
    if retval != 0:
        raise LibraryError(
            ReportItem.error(reports.messages.CibPushError(stderr, stdout))
        )


def diff_cibs_xml(
    runner: CommandRunner,
    reporter: ReportProcessor,
    cib_old_xml,
    cib_new_xml,
):
    """
    Return xml diff of two CIBs

    runner
    reporter
    string cib_old_xml -- original CIB
    string cib_new_xml -- modified CIB
    """
    try:
        cib_old_tmp_file = write_tmpfile(cib_old_xml)
        reporter.report(
            ReportItem.debug(
                reports.messages.TmpFileWrite(
                    cib_old_tmp_file.name, cib_old_xml
                )
            )
        )
        cib_new_tmp_file = write_tmpfile(cib_new_xml)
        reporter.report(
            ReportItem.debug(
                reports.messages.TmpFileWrite(
                    cib_new_tmp_file.name, cib_new_xml
                )
            )
        )
    except EnvironmentError as e:
        raise LibraryError(
            ReportItem.error(reports.messages.CibSaveTmpError(str(e)))
        ) from e
    command = [
        __exec("crm_diff"),
        "--original",
        cib_old_tmp_file.name,
        "--new",
        cib_new_tmp_file.name,
        "--no-version",
    ]
    #  0 (CRM_EX_OK) - success with no difference
    #  1 (CRM_EX_ERROR) - success with difference
    # 64 (CRM_EX_USAGE) - usage error
    # 65 (CRM_EX_DATAERR) - XML fragments not parseable
    stdout, stderr, retval = runner.run(command)
    if retval == 0:
        return ""
    if retval > 1:
        raise LibraryError(
            ReportItem.error(
                reports.messages.CibDiffError(
                    stderr.strip(), cib_old_xml, cib_new_xml
                )
            )
        )
    return stdout.strip()


def ensure_cib_version(
    runner: CommandRunner,
    cib: _Element,
    version: Version,
    fail_if_version_not_met: bool = True,
) -> Tuple[_Element, bool]:
    """
    Make sure CIB complies to specified schema version (or newer), upgrade CIB
    if necessary. Raise on error. Raise if CIB cannot be upgraded enough to
    meet the required version unless fail_if_version_not_met is set to False.
    Return tuple(upgraded_cib, was_upgraded)

    This method ensures that specified cib is verified by pacemaker with
    version 'version' or newer. If cib doesn't correspond to this version,
    method will try to upgrade cib.
    Returns cib which was verified by pacemaker version 'version' or later.
    Raises LibraryError on any failure.

    runner -- runner
    cib -- cib tree
    version -- required cib version
    fail_if_version_not_met -- allows a 'nice to have' cib upgrade
    """
    version_pre_upgrade = get_pacemaker_version_by_which_cib_was_validated(cib)
    if version_pre_upgrade >= version:
        return cib, False

    _upgrade_cib(runner)
    new_cib_xml = get_cib_xml(runner)

    try:
        new_cib = parse_cib_xml(new_cib_xml)
    except (etree.XMLSyntaxError, etree.DocumentInvalid) as e:
        raise LibraryError(
            ReportItem.error(reports.messages.CibUpgradeFailed(str(e)))
        ) from e

    version_post_upgrade = get_pacemaker_version_by_which_cib_was_validated(
        new_cib
    )
    if version_post_upgrade >= version or not fail_if_version_not_met:
        return new_cib, version_post_upgrade > version_pre_upgrade

    raise LibraryError(
        ReportItem.error(
            reports.messages.CibUpgradeFailedToMinimalRequiredVersion(
                str(version_post_upgrade), str(version)
            )
        )
    )


def _upgrade_cib(runner):
    """
    Upgrade CIB to the latest schema available locally or clusterwise.
    CommandRunner runner
    """
    stdout, stderr, retval = runner.run(
        [__exec("cibadmin"), "--upgrade", "--force"]
    )
    # If we are already on the latest schema available, cibadmin exits with 0.
    # That is fine. We do not know here what version is required anyway. The
    # caller knows that and is responsible for dealing with it.
    if retval != 0:
        raise LibraryError(
            ReportItem.error(
                reports.messages.CibUpgradeFailed(
                    join_multilines([stderr, stdout])
                )
            )
        )


def simulate_cib_xml(runner, cib_xml):
    """
    Run crm_simulate to get effects the cib would have on the live cluster

    CommandRunner runner -- runner
    string cib_xml -- CIB XML to simulate
    """
    try:
        new_cib_file = write_tmpfile(None)
        transitions_file = write_tmpfile(None)
    except OSError as e:
        raise LibraryError(
            ReportItem.error(
                reports.messages.CibSimulateError(format_os_error(e))
            )
        ) from e

    cmd = [
        __exec("crm_simulate"),
        "--simulate",
        "--save-output",
        new_cib_file.name,
        "--save-graph",
        transitions_file.name,
        "--xml-pipe",
    ]
    stdout, stderr, retval = runner.run(cmd, stdin_string=cib_xml)
    if retval != 0:
        raise LibraryError(
            ReportItem.error(reports.messages.CibSimulateError(stderr.strip()))
        )

    try:
        new_cib_file.seek(0)
        transitions_file.seek(0)
        new_cib_xml = new_cib_file.read()
        transitions_xml = transitions_file.read()
        new_cib_file.close()
        transitions_file.close()
        return stdout, transitions_xml, new_cib_xml
    except OSError as e:
        raise LibraryError(
            ReportItem.error(
                reports.messages.CibSimulateError(format_os_error(e))
            )
        ) from e


def simulate_cib(runner, cib):
    """
    Run crm_simulate to get effects the cib would have on the live cluster

    CommandRunner runner -- runner
    etree cib -- cib tree to simulate
    """
    cib_xml = etree_to_str(cib)
    try:
        plaintext_result, transitions_xml, new_cib_xml = simulate_cib_xml(
            runner, cib_xml
        )
        return (
            plaintext_result.strip(),
            xml_fromstring(transitions_xml),
            xml_fromstring(new_cib_xml),
        )
    except (etree.XMLSyntaxError, etree.DocumentInvalid) as e:
        raise LibraryError(
            ReportItem.error(reports.messages.CibSimulateError(str(e)))
        ) from e


### wait for idle


def wait_for_idle(runner, timeout=None):
    """
    Run waiting command. Raise LibraryError if command failed.

    runner is preconfigured object for running external programs
    string timeout is waiting timeout
    """
    args = [__exec("crm_resource"), "--wait"]
    if timeout is not None:
        args.append("--timeout={0}".format(timeout))
    stdout, stderr, retval = runner.run(args)
    if retval != 0:
        # Usefull info goes to stderr - not only error messages, a list of
        # pending actions in case of timeout goes there as well.
        # We use stdout just to be sure if that's get changed.
        if retval == __EXITCODE_WAIT_TIMEOUT:
            raise LibraryError(
                ReportItem.error(
                    reports.messages.WaitForIdleTimedOut(
                        join_multilines([stderr, stdout])
                    )
                )
            )
        raise LibraryError(
            ReportItem.error(
                reports.messages.WaitForIdleError(
                    join_multilines([stderr, stdout])
                )
            )
        )


### nodes


def get_local_node_name(runner):
    stdout, stderr, retval = runner.run([__exec("crm_node"), "--name"])
    if retval != 0:
        klass = (
            PacemakerNotConnectedException
            if retval == __EXITCODE_NOT_CONNECTED
            else LibraryError
        )
        raise klass(
            ReportItem.error(
                reports.messages.PacemakerLocalNodeNameNotFound(
                    join_multilines([stderr, stdout])
                )
            )
        )
    return stdout.strip()


def get_local_node_status(runner):
    try:
        cluster_status = ClusterState(get_cluster_status_dom(runner))
        node_name = get_local_node_name(runner)
    except PacemakerNotConnectedException:
        return {"offline": True}
    for node_status in cluster_status.node_section.nodes:
        if node_status.attrs.name == node_name:
            result = {
                "offline": False,
            }
            for attr in (
                "id",
                "name",
                "type",
                "online",
                "standby",
                "standby_onfail",
                "maintenance",
                "pending",
                "unclean",
                "shutdown",
                "expected_up",
                "is_dc",
                "resources_running",
            ):
                result[attr] = getattr(node_status.attrs, attr)
            return result
    raise LibraryError(
        ReportItem.error(reports.messages.NodeNotFound(node_name))
    )


def remove_node(runner, node_name):
    stdout, stderr, retval = runner.run(
        [
            __exec("crm_node"),
            "--force",
            "--remove",
            node_name,
        ]
    )
    if retval != 0:
        raise LibraryError(
            ReportItem.error(
                reports.messages.NodeRemoveInPacemakerFailed(
                    node_list_to_remove=[node_name],
                    reason=join_multilines([stderr, stdout]),
                )
            )
        )


### resources


def resource_cleanup(
    runner: CommandRunner,
    resource: Optional[str] = None,
    node: Optional[str] = None,
    operation: Optional[str] = None,
    interval: Optional[str] = None,
    strict: bool = False,
):
    cmd = [__exec("crm_resource"), "--cleanup"]
    if resource:
        cmd.extend(["--resource", resource])
    if node:
        cmd.extend(["--node", node])
    if operation:
        cmd.extend(["--operation", operation])
    if interval:
        cmd.extend(["--interval", interval])
    if strict:
        cmd.extend(["--force"])

    stdout, stderr, retval = runner.run(cmd)

    if retval != 0:
        raise LibraryError(
            ReportItem.error(
                reports.messages.ResourceCleanupError(
                    join_multilines([stderr, stdout]), resource, node
                )
            )
        )
    # usefull output (what has been done) goes to stderr
    return join_multilines([stdout, stderr])


def resource_refresh(
    runner: CommandRunner,
    resource: Optional[str] = None,
    node: Optional[str] = None,
    strict: bool = False,
    force: bool = False,
):
    if not force and not node and not resource:
        summary = ClusterState(get_cluster_status_dom(runner)).summary
        operations = summary.nodes.attrs.count * summary.resources.attrs.count
        if operations > __RESOURCE_REFRESH_OPERATION_COUNT_THRESHOLD:
            raise LibraryError(
                ReportItem(
                    reports.item.ReportItemSeverity.error(
                        reports.codes.FORCE_LOAD_THRESHOLD
                    ),
                    reports.messages.ResourceRefreshTooTimeConsuming(
                        __RESOURCE_REFRESH_OPERATION_COUNT_THRESHOLD
                    ),
                )
            )

    cmd = [__exec("crm_resource"), "--refresh"]
    if resource:
        cmd.extend(["--resource", resource])
    if node:
        cmd.extend(["--node", node])
    if strict:
        cmd.extend(["--force"])

    stdout, stderr, retval = runner.run(cmd)

    if retval != 0:
        raise LibraryError(
            ReportItem.error(
                reports.messages.ResourceRefreshError(
                    join_multilines([stderr, stdout]), resource, node
                )
            )
        )
    # usefull output (what has been done) goes to stderr
    return join_multilines([stdout, stderr])


def resource_move(runner, resource_id, node=None, master=False, lifetime=None):
    return _resource_move_ban_clear(
        runner,
        "--move",
        resource_id,
        node=node,
        master=master,
        lifetime=lifetime,
    )


def resource_ban(runner, resource_id, node=None, master=False, lifetime=None):
    return _resource_move_ban_clear(
        runner,
        "--ban",
        resource_id,
        node=node,
        master=master,
        lifetime=lifetime,
    )


def resource_unmove_unban(
    runner, resource_id, node=None, master=False, expired=False
):
    return _resource_move_ban_clear(
        runner,
        "--clear",
        resource_id,
        node=node,
        master=master,
        expired=expired,
    )


def has_resource_unmove_unban_expired_support(runner):
    return _is_in_pcmk_tool_help(runner, "crm_resource", ["--expired"])


def _resource_move_ban_clear(
    runner,
    action,
    resource_id,
    node=None,
    master=False,
    lifetime=None,
    expired=False,
):
    command = [
        __exec("crm_resource"),
        action,
        "--resource",
        resource_id,
    ]
    if node:
        command.extend(["--node", node])
    if master:
        command.extend(["--master"])
    if lifetime:
        command.extend(["--lifetime", lifetime])
    if expired:
        command.extend(["--expired"])
    stdout, stderr, retval = runner.run(command)
    return stdout, stderr, retval


### fence history


def is_fence_history_supported_status(runner: CommandRunner) -> bool:
    return _is_in_pcmk_tool_help(runner, "crm_mon", ["--fence-history"])


def is_fence_history_supported_management(runner: CommandRunner) -> bool:
    return _is_in_pcmk_tool_help(
        runner, "stonith_admin", ["--history", "--broadcast", "--cleanup"]
    )


def fence_history_cleanup(runner, node=None):
    return _run_fence_history_command(runner, "--cleanup", node)


def fence_history_text(runner, node=None):
    return _run_fence_history_command(runner, "--verbose", node)


def fence_history_update(runner):
    # Pacemaker always prints "gather fencing-history from all nodes" even if a
    # node is specified. However, --history expects a value, so we must provide
    # it. Otherwise "--broadcast" would be considered a value of "--history".
    return _run_fence_history_command(runner, "--broadcast", node=None)


def _run_fence_history_command(runner, command, node=None):
    stdout, stderr, retval = runner.run(
        [__exec("stonith_admin"), "--history", node if node else "*", command]
    )
    if retval != 0:
        raise FenceHistoryCommandErrorException(
            join_multilines([stderr, stdout])
        )
    return stdout.strip()


### tools


def has_rule_in_effect_status_tool() -> bool:
    return os.path.isfile(__exec("crm_rule"))


def get_rule_in_effect_status(
    runner: CommandRunner, cib_xml: str, rule_id: str
) -> CibRuleInEffectStatus:
    """
    Figure out if a rule is in effect, expired or not yet in effect

    runner -- a class for running external processes
    cib_xml -- CIB containing rules
    rule_id -- ID of the rule to be checked
    """
    # TODO Once crm_rule is capable of evaluating more than one rule per go, we
    # should make use of it. Running the tool for each rule may really slow pcs
    # down.
    translation_map = {
        0: CibRuleInEffectStatus.IN_EFFECT,
        110: CibRuleInEffectStatus.EXPIRED,
        111: CibRuleInEffectStatus.NOT_YET_IN_EFFECT,
        # 105:non-existent
        # 112: undetermined (rule is too complicated for current implementation)
    }
    dummy_stdout, dummy_stderr, retval = runner.run(
        [__exec("crm_rule"), "--check", "--rule", rule_id, "--xml-text", "-"],
        stdin_string=cib_xml,
    )
    return translation_map.get(retval, CibRuleInEffectStatus.UNKNOWN)


def get_status_from_api_result(dom: _Element) -> api_result.Status:
    errors = []
    status_el = cast(_Element, dom.find("./status"))
    errors_el = status_el.find("errors")
    if errors_el is not None:
        errors = [
            str((error_el.text or "")).strip()
            for error_el in errors_el.iterfind("error")
        ]
    return api_result.Status(
        code=int(str(status_el.get("code"))),
        message=str(status_el.get("message")),
        errors=errors,
    )


# shortcut for getting a full path to a pacemaker executable
def __exec(name):
    return os.path.join(settings.pacemaker_binaries, name)


def _is_in_pcmk_tool_help(
    runner: CommandRunner, tool: str, text_list: Iterable[str]
) -> bool:
    stdout, stderr, dummy_retval = runner.run([__exec(tool), "--help-all"])
    # Help goes to stderr but we check stdout as well if that gets changed. Use
    # generators in all to return early.
    return all(text in stderr for text in text_list) or all(
        text in stdout for text in text_list
    )


def is_getting_resource_digest_supported(runner):
    return _is_in_pcmk_tool_help(runner, "crm_resource", "--digests")


def get_resource_digests(
    runner: CommandRunner,
    resource_id: str,
    node_name: str,
    resource_options: Dict[str, str],
    crm_meta_attributes: Optional[Dict[str, Optional[str]]] = None,
) -> Dict[str, Optional[str]]:
    # pylint: disable=too-many-locals
    if crm_meta_attributes is None:
        crm_meta_attributes = dict()
    command = [
        __exec("crm_resource"),
        "--digests",
        "--resource",
        resource_id,
        "--node",
        node_name,
        "--output-as",
        "xml",
        *[f"{key}={value}" for key, value in resource_options.items()],
        *[
            f"CRM_meta_{key}={value}"
            for key, value in crm_meta_attributes.items()
            if value is not None
        ],
    ]
    stdout, stderr, retval = runner.run(command)

    def error_exception(message):
        return LibraryError(
            ReportItem.error(
                reports.messages.UnableToGetResourceOperationDigests(message)
            )
        )

    try:
        dom = xml_fromstring(stdout)
        if os.path.isfile(settings.pacemaker_api_result_schema):
            etree.RelaxNG(
                file=settings.pacemaker_api_result_schema
            ).assertValid(dom)
    except (etree.XMLSyntaxError, etree.DocumentInvalid) as e:
        raise error_exception(join_multilines([stderr, stdout])) from e

    if retval != 0:
        status = get_status_from_api_result(dom)
        raise error_exception(
            join_multilines([status.message] + list(status.errors))
        )

    digests = {}
    for digest_type in ["all", "nonprivate", "nonreloadable"]:
        xpath_result = cast(
            List[str],
            dom.xpath(f'./digests/digest[@type="{digest_type}"]/@hash'),
        )
        digests[digest_type] = xpath_result[0] if xpath_result else None
    if not any(digests.values()):
        raise error_exception(join_multilines([stderr, stdout]))
    return digests
