from __future__ import (
    absolute_import,
    division,
    print_function,
)

from pcs.common import report_codes
from pcs.lib.errors import ReportItemSeverity as severities


def complete_state_resources(resource_status):
    for resource in resource_status.xpath(".//resource"):
        _default_element_attributes(
            resource,
            {
                "active": "true",
                "managed": "true",
                "failed": "false",
                "failure_ignored": "false",
                "nodes_running_on": "1",
                "orphaned": "false",
                "resource_agent": "ocf::heartbeat:Dummy",
                "role": "Started",
            }
        )
    for clone in resource_status.xpath(".//clone"):
        _default_element_attributes(
            clone,
            {
                "failed": "false",
                "failure_ignored": "false",
            }
        )
    for bundle in resource_status.xpath(".//bundle"):
        _default_element_attributes(
            bundle,
            {
                "type": "docker",
                "image": "image:name",
                "unique": "false",
                "failed": "false",
            }
        )
    return resource_status


def _default_element_attributes(element, default_attributes):
    for name, value in default_attributes.items():
        if name not in element.attrib:
            element.attrib[name] = value

def create_report(severity, code, info, force_code=None):
    return severity, code, info, force_code

def report_variation(report, **info):
    updated_info = report[2].copy()
    updated_info.update(info)
    return create_report(report[0], report[1], updated_info, report[3])

def debug(code, **kwargs):
    return create_report(severities.DEBUG, code, kwargs)

def warn(code, **kwargs):
    return create_report(severities.WARNING, code, kwargs)

def error(code, force_code=None, **kwargs):
    return create_report(severities.ERROR, code, kwargs, force_code)

def info(code, **kwargs):
    return create_report(severities.INFO, code, kwargs)

class ReportStore(object):
    def __init__(self, names=None, reports=None):
        if not names:
            names = []

        duplicate_names = set([n for n in names if names.count(n) > 1])
        if duplicate_names:
            raise AssertionError(
                "Duplicate names are not allowed in ReportStore. "
                " Found duplications:\n  '{0}'".format(
                    "'\n  '".join(duplicate_names)
                )
            )

        self.__names = names or []
        self.__reports = reports or []

    @property
    def reports(self):
        return list(self.__reports)

    def adapt(self, name, **info):
        index = self.__names.index(name)
        return ReportStore(self.__names, [
            report if i != index else report_variation(report, **info)
            for i, report in enumerate(self.__reports)
        ])

    def info(self, name, code, **kwargs):
        return self.__append(name, info(code, **kwargs))

    def warn(self, name, code, **kwargs):
        return self.__append(name, warn(code, **kwargs))

    def error(self, name, code, force_code=None, **kwargs):
        return self.__append(name, error(code, force_code=force_code, **kwargs))

    def copy(self, name, as_name, **info):
        return self.__append(as_name, report_variation(self[name], **info))

    def remove(self, *name_list):
        names, reports = zip(*[
            (name, report) for name, report in zip(self.__names, self.__reports)
            if name not in name_list
        ])
        return ReportStore(list(names), list(reports))

    def __getitem__(self, spec):
        if not isinstance(spec, slice):
            return self.__reports[self.__names.index(spec)]

        assert spec.step is None, "Step is not supported in slicing"
        start = None if spec.start is None else self.__names.index(spec.start)
        stop = None if spec.stop is None else self.__names.index(spec.stop)

        return ReportStore(self.__names[start:stop], self.__reports[start:stop])

    def __append(self, name, report):
        return ReportStore(self.__names + [name], self.__reports + [report])

def report_not_found(res_id, context_type=""):
    return (
        severities.ERROR,
        report_codes.ID_NOT_FOUND,
        {
            "context_type": context_type,
            "context_id": "",
            "id": res_id,
            "expected_types": [
                "bundle", "clone", "group", "master", "primitive"
            ],
        },
        None
    )

def report_resource_not_running(resource, severity=severities.INFO):
    return (
        severity,
        report_codes.RESOURCE_DOES_NOT_RUN,
        {
            "resource_id": resource,
        },
        None
    )

def report_resource_running(resource, roles, severity=severities.INFO):
    return (
        severity,
        report_codes.RESOURCE_RUNNING_ON_NODES,
        {
            "resource_id": resource,
            "roles_with_nodes": roles,
        },
        None
    )

def report_unexpected_element(element_id, elemet_type, expected_types):
    return (
        severities.ERROR,
        report_codes.ID_BELONGS_TO_UNEXPECTED_TYPE,
        {
            "id": element_id,
            "expected_types": expected_types,
            "current_type": elemet_type,
        },
        None
    )

def report_not_for_bundles(element_id):
    return report_unexpected_element(
        element_id,
        "bundle",
        ["clone", "master", "group", "primitive"]
    )

def report_wait_for_idle_timed_out(reason):
    return (
        severities.ERROR,
        report_codes.WAIT_FOR_IDLE_TIMED_OUT,
        {
            "reason": reason.strip(),
        },
        None
    )
