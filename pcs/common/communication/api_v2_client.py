import json
import os
import ssl
import time
from collections.abc import Generator, Mapping
from ipaddress import AddressValueError, IPv6Address
from logging import Logger
from typing import Any, TypeVar
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from pcs import settings
from pcs.common.async_tasks.dto import TaskIdentDto, TaskResultDto
from pcs.common.async_tasks.types import TaskFinishType
from pcs.common.interface.dto import DataTransferObject, from_dict, to_dict
from pcs.common.reports import report_dto_to_item
from pcs.common.reports.item import ReportItem, ReportItemContext
from pcs.lib.external import is_proxy_set

# There can be self signed certificates.
_UNVERIFIED_SSL_CONTEXT = ssl._create_unverified_context()  # noqa: SLF001

_DTO = TypeVar("_DTO", bound=DataTransferObject)


def _format_addr_for_url(addr: str) -> str:
    try:
        IPv6Address(addr)
        return f"[{addr}]"
    except AddressValueError:
        return addr


class ApiV2CommunicationError(Exception):
    pass


class ApiV2RequestError(Exception):
    """The request payload is invalid; retrying on another node won't help."""


class NodeConnector:
    def __init__(
        self,
        logger: Logger,
        addr: str,
        port: int,
        token: str,
        node_name: str,
        effective_username: str | None,
        effective_groups: list[str] | None,
        request_timeout: int,
    ):
        self._logger = logger
        self._host = f"{_format_addr_for_url(addr)}:{port}"
        self._token = token
        self._node_name = node_name
        self._effective_username = effective_username
        self._effective_groups = effective_groups
        self._request_timeout = request_timeout

    def task_create(self, cmd_payload: Mapping[str, Any]) -> str:
        payload = {
            **cmd_payload,
            "options": {
                **cmd_payload.get("options", {}),
                **self._effective_user_options(),
            },
        }
        request = Request(
            f"https://{self._host}/api/v2/task/create",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Cookie": f"token={self._token}",
            },
            method="POST",
        )
        response = self._send_request(request, request_error_on_400=True)
        task_ident = self._parse_response(response, TaskIdentDto).task_ident
        self._logger.info("Created task %s on %s", task_ident, self._host)
        return task_ident

    def task_result(
        self,
        task_ident: str,
        poll_interval: float = 1.0,
    ) -> Generator[tuple[list[ReportItem], bool, Any], None, None]:
        request = Request(
            f"https://{self._host}/api/v2/task/result?task_ident={task_ident}",
            headers={"Cookie": f"token={self._token}"},
            method="GET",
        )
        reports_seen = 0
        context = ReportItemContext(self._node_name)

        # Poll indefinitely until node returns a finished state. No timeout
        # parameter — APIv2 supports long-running tasks. This hardcoded
        # behavior is intentional — no client needs anything else.
        while True:
            response = self._send_request(request)
            result_dto = self._parse_response(response, TaskResultDto)

            new_reports_dto = result_dto.reports[reports_seen:]
            reports_seen = len(result_dto.reports)

            self._log_poll_cycle(task_ident, result_dto, new_reports_dto)

            new_reports = [
                report_dto_to_item(r, context) for r in new_reports_dto
            ]
            if result_dto.task_finish_type == TaskFinishType.UNFINISHED:
                if new_reports:
                    yield new_reports, False, None
                time.sleep(poll_interval)
                continue

            yield (
                new_reports,
                result_dto.task_finish_type == TaskFinishType.SUCCESS,
                result_dto.result,
            )
            return

    def _effective_user_options(self) -> dict[str, Any]:
        options: dict[str, Any] = {}
        if self._effective_username:
            options["effective_username"] = self._effective_username
        if self._effective_groups:
            options["effective_groups"] = self._effective_groups
        return options

    def _parse_response(self, response: str, dto_class: type[_DTO]) -> _DTO:
        try:
            return from_dict(dto_class, json.loads(response))
        except Exception as e:
            self._logger.error(
                "Response from %s does not conform to %s %s",
                self._host,
                dto_class.__name__,
                e,
            )
            raise ApiV2CommunicationError(f"Unexpected response: {e}") from e

    def _send_request(
        self, request: Request, request_error_on_400: bool = False
    ) -> str:
        try:
            self._logger.info("Sending request to %s", request.full_url)
            # Timeout applies to each individual HTTP request, not to the
            # overall operation. Both task/create and task/result are
            # lightweight server-side operations that should respond quickly.
            # The long-running part is the polling loop in task_result, which
            # is intentionally unbounded.
            with urlopen(
                request,
                context=_UNVERIFIED_SSL_CONTEXT,
                timeout=self._request_timeout,
            ) as response:
                return response.read().decode("utf-8")
        except HTTPError as e:
            self._logger.info(
                "HTTP error: %s %s for %s", e.code, e.reason, request.full_url
            )
            # HTTP 400 from task/create means the payload is inherently
            # invalid — no node can process it. All 400 cases (api_v2.py):
            #   - malformed JSON body (prepare)
            #   - missing request body (RequestBodyMissingError)
            #   - missing required key in CommandDto (_from_dict_exc_handled)
            #   - unexpected keys in request body (_from_dict_exc_handled)
            #   - other payload structure violations (_from_dict_exc_handled)
            if request_error_on_400 and e.code == 400:
                raise ApiV2RequestError(
                    f"HTTP error {e.code}: {e.reason}"
                ) from e
            raise ApiV2CommunicationError(
                f"HTTP error {e.code}: {e.reason}"
            ) from e
        except URLError as e:
            self._logger.info(
                "URL error: %s for %s", e.reason, request.full_url
            )
            # Proxy env vars (https_proxy, all_proxy) are respected by
            # urllib and may cause connection failures when set
            # unintentionally. We intentionally do not disable proxy — it
            # can be legitimate (e.g. webUI managing a remote cluster).
            # Instead, we warn to aid debugging, consistent with the rest
            # of the codebase (NodeCommunicator, pcs/utils.py, pcsd/pcs.rb).
            # See: https://bugzilla.redhat.com/show_bug.cgi?id=1315627
            if is_proxy_set(os.environ):
                self._logger.warning(
                    "Proxy is set in environment variables, try disabling it"
                )
            raise ApiV2CommunicationError(f"URL error: {e.reason}") from e
        except Exception as e:
            self._logger.info(
                "Unexpected error %s for %s",
                e.__class__.__name__,
                request.full_url,
            )
            raise ApiV2CommunicationError(
                f"Unexpected error: {e.__class__.__name__}"
            ) from e

    def _log_poll_cycle(
        self,
        task_ident: str,
        result_dto: TaskResultDto,
        new_reports_dto: list,
    ) -> None:
        finish_type = result_dto.task_finish_type
        kill_reason = result_dto.kill_reason
        ident = task_ident
        reports = [to_dict(r) for r in new_reports_dto]

        if reports:
            self._logger.debug("Task %s new reports: %s", ident, reports)

        if finish_type == TaskFinishType.UNFINISHED:
            self._logger.info("Task %s status: %s", ident, finish_type)
            return

        self._logger.info("Task %s finished with status %s", ident, finish_type)

        if finish_type == TaskFinishType.SUCCESS:
            self._logger.info("Task %s result: %s", ident, result_dto.result)

        if finish_type == TaskFinishType.KILL and kill_reason:
            self._logger.info("Task %s kill reason: %s", ident, kill_reason)


class ApiV2Client:
    CommunicationError = ApiV2CommunicationError
    RequestError = ApiV2RequestError

    def __init__(
        self,
        logger: Logger,
        effective_username: str | None = None,
        effective_groups: list[str] | None = None,
        request_timeout: int | None = None,
    ):
        self._logger = logger
        self._effective_username = effective_username
        self._effective_groups = effective_groups
        self._request_timeout = (
            request_timeout
            if request_timeout is not None
            else settings.default_request_timeout
        )

    def node_connector(
        self, addr: str, port: int, token: str, node_name: str
    ) -> NodeConnector:
        return NodeConnector(
            self._logger,
            addr,
            port,
            token,
            node_name,
            self._effective_username,
            self._effective_groups,
            self._request_timeout,
        )
