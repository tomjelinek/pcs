from functools import partial
from typing import Optional

from lxml import etree
from lxml.etree import _Element

from pcs.common import reports
from pcs.lib import validate
from pcs.lib.cib.tools import (
    IdProvider,
    check_new_id_applicable,
    does_id_exist,
    find_element_by_tag_and_id,
)
from pcs.lib.errors import LibraryError

TAG_GROUP = "acl_group"
TAG_ROLE = "acl_role"
TAG_TARGET = "acl_target"
TAG_PERMISSION = "acl_permission"

PermissionInfoList = list[tuple[str, str, str]]


def validate_permissions(
    tree: _Element, permission_info_list: PermissionInfoList
) -> reports.ReportItemList:
    """
    Validate given permission list

    tree -- cib tree
    permission_info_list -- list of tuples like this:
        ("read|write|deny", "xpath|id", <id-or-xpath-string>)
    """
    report_items = []
    allowed_permissions = ["read", "write", "deny"]
    allowed_scopes = ["xpath", "id"]
    for permission, scope_type, scope in permission_info_list:
        if permission not in allowed_permissions:
            report_items.append(
                reports.ReportItem.error(
                    reports.messages.InvalidOptionValue(
                        "permission", permission, allowed_permissions
                    )
                )
            )

        if scope_type not in allowed_scopes:
            report_items.append(
                reports.ReportItem.error(
                    reports.messages.InvalidOptionValue(
                        "scope type", scope_type, allowed_scopes
                    )
                )
            )

        if scope_type == "id" and not does_id_exist(tree, scope):
            report_items.append(
                reports.ReportItem.error(
                    reports.messages.IdNotFound(scope, ["id"])
                )
            )

    return report_items


def _find(tag, acl_section, element_id, none_if_id_unused=False, id_types=None):
    return find_element_by_tag_and_id(
        tag,
        acl_section,
        element_id,
        id_types=id_types,
        none_if_id_unused=none_if_id_unused,
    )


find_group = partial(_find, TAG_GROUP)
find_role = partial(_find, TAG_ROLE)
find_target = partial(_find, TAG_TARGET)


# DEPRECATED in the first 0.12 version
def find_target_or_group(acl_section, target_or_group_id):
    """
    Returns acl_target or acl_group element with id target_or_group_id. Target
    element has bigger priority so if there are target and group with the same
    id only target element will be affected by this function.
    Raises LibraryError if there is no target or group element with
    specified id.

    This approach is DEPRECATED and it is there only for backward compatibility
    reason. It is better to know explicitly whether we need target(user) or
    group.

    acl_section -- cib etree node
    target_or_group_id -- id of target/group element which should be returned
    """
    target = find_target(
        acl_section, target_or_group_id, none_if_id_unused=True
    )

    if target is not None:
        return target

    return find_group(
        acl_section, target_or_group_id, id_types=[TAG_GROUP, TAG_TARGET]
    )


def validate_create_role(
    id_provider: IdProvider, role_id: str, description: Optional[str] = None
) -> reports.ReportItemList:
    """
    Validate creating a new role

    id_provider -- id provider
    role_id -- id of desired role
    description -- role description
    """
    del description
    validators = [
        validate.ValueId("role id", "ACL role", id_provider),
    ]
    return validate.ValidatorAll(validators).validate({"role id": role_id})


def create_role(
    acl_section: _Element, role_id: str, description: Optional[str] = None
) -> _Element:
    """
    Create new role element, add it to cib and return it

    acl_section -- parent element for the new role
    role_id -- id of desired role
    description -- role description
    """
    role = etree.SubElement(acl_section, TAG_ROLE, id=role_id)
    if description:
        role.set("description", description)
    return role


def remove_role(acl_section, role_id, autodelete_users_groups=False):
    """
    Remove role with specified id from CIB and all references to it.

    acl_section -- etree node
    role_id -- id of role to be removed
    autodelete_users_group -- if True remove targets with no role after removing
    """
    acl_role = find_role(acl_section, role_id)
    acl_role.getparent().remove(acl_role)
    for role_el in acl_section.xpath(".//role[@id=$role_id]", role_id=role_id):
        role_parent = role_el.getparent()
        role_parent.remove(role_el)
        if autodelete_users_groups and role_parent.find(".//role") is None:
            role_parent.getparent().remove(role_parent)


def _assign_role(acl_section, role_id, target_el):
    try:
        role_el = find_role(acl_section, role_id)
    except LibraryError as e:
        return list(e.args)
    assigned_role_list = target_el.xpath(
        "./role[@id=$role_id]", role_id=role_el.get("id")
    )
    if assigned_role_list:
        return [
            reports.ReportItem.error(
                reports.messages.CibAclRoleIsAlreadyAssignedToTarget(
                    role_el.get("id"), target_el.get("id")
                )
            )
        ]
    etree.SubElement(target_el, "role", {"id": role_el.get("id")})
    return []


def assign_role(acl_section, role_id, target_el):
    """
    Assign role element to specified target/group element.
    Raise LibraryError if role is already assigned to target/group.

    target_el -- etree element of target/group to which role should be assign
    role_el -- etree element of role
    """
    report_list = _assign_role(acl_section, role_id, target_el)
    if report_list:
        raise LibraryError(*report_list)


def assign_all_roles(acl_section, role_id_list, element):
    """
    Assign roles from role_id_list to element.
    Raises LibraryError on any failure.

    acl_section -- cib etree node
    element -- element to which specified roles should be assigned
    role_id_list -- list of role id
    """
    report_list = []
    for role_id in role_id_list:
        report_list.extend(_assign_role(acl_section, role_id, element))
    if report_list:
        raise LibraryError(*report_list)


def unassign_role(target_el, role_id, autodelete_target=False):
    """
    Unassign role with role_id from specified target/user target_el.
    Raise LibraryError if role is not assigned to target/group.

    target_el -- etree element of target/group from which role should be
        unassign
    role_id -- id of role
    autodelete_target -- if True remove target_el if there is no role assigned
    """
    assigned_role_list = target_el.xpath(
        "./role[@id=$role_id]", role_id=role_id
    )
    if not assigned_role_list:
        raise LibraryError(
            reports.ReportItem.error(
                reports.messages.CibAclRoleIsNotAssignedToTarget(
                    role_id, target_el.get("id")
                )
            )
        )
    for assigned_role in assigned_role_list:
        target_el.remove(assigned_role)
    if autodelete_target and target_el.find("./role") is None:
        target_el.getparent().remove(target_el)


def create_target(acl_section, target_id):
    """
    Creates new acl_target element with id target_id.
    Raises LibraryError if target with specified id already exists.

    acl_section -- etree node
    target_id -- id of new target
    """
    # id of element acl_target is not type ID in CIB ACL schema so we don't need
    # to check if it is unique ID in whole CIB
    if acl_section.xpath(
        f"./{TAG_TARGET}[@id=$target_id]", target_id=target_id
    ):
        raise LibraryError(
            reports.ReportItem.error(
                reports.messages.CibAclTargetAlreadyExists(target_id)
            )
        )
    return etree.SubElement(acl_section, TAG_TARGET, id=target_id)


def create_group(acl_section, group_id):
    """
    Creates new acl_group element with specified id.
    Raises LibraryError if tree contains element with id group_id.

    acl_section -- etree node
    group_id -- id of new group
    """
    check_new_id_applicable(acl_section, "ACL group", group_id)
    return etree.SubElement(acl_section, TAG_GROUP, id=group_id)


def remove_target(acl_section, target_id):
    """
    Removes acl_target element from acl_section with specified id.
    Raises LibraryError if target with id target_id doesn't exist.

    acl_section -- etree node
    target_id -- id of target element to remove
    """
    target = find_target(acl_section, target_id)
    target.getparent().remove(target)


def remove_group(acl_section, group_id):
    """
    Removes acl_group element from tree with specified id.
    Raises LibraryError if group with id group_id doesn't exist.

    acl_section -- etree node
    group_id -- id of group element to remove
    """
    group = find_group(acl_section, group_id)
    group.getparent().remove(group)


def add_permissions_to_role(
    role_el: _Element,
    permission_info_list: PermissionInfoList,
    id_provider: IdProvider,
) -> None:
    """
    Add permissions from permission_info_list to role_el.

    role_el -- acl_role element to which permissions should be added
    permission_info_list -- list of tuples,
        each contains (permission, scope_type, scope)
    id_provider -- id provider
    """
    area_type_attribute_map = {
        "xpath": "xpath",
        "id": "reference",
    }
    for permission, scope_type, scope in permission_info_list:
        perm = etree.SubElement(role_el, "acl_permission")
        perm.set(
            "id",
            id_provider.allocate_id(
                "{0}-{1}".format(role_el.get("id", "role"), permission)
            ),
        )
        perm.set("kind", permission)
        perm.set(area_type_attribute_map[scope_type], scope)


def remove_permission(acl_section, permission_id):
    """
    Remove permission with id permission_id from acl_section.

    acl_section -- etree node
    permission_id -- id of permission element to be removed
    """
    permission = _find(TAG_PERMISSION, acl_section, permission_id)
    permission.getparent().remove(permission)


def get_role_list(acl_section):
    """
    Returns list of all acl_role elements from acl_section.
    Format of items of output list:
        {
            "id": <role-id>,
            "description": <role-description>,
            "permission_list": [<see function _get_all_permission_list>, ...]
        }

    acl_section -- etree node
    """
    output_list = []
    for role_el in acl_section.xpath(f"./{TAG_ROLE}"):
        role = {key: role_el.get(key) for key in ["id", "description"]}
        role["permission_list"] = _get_permission_list(role_el)
        output_list.append(role)
    return output_list


def _get_permission_list(role_el):
    """
    Return list of all permissions of role element role_el.
    Format of item of output list (if attribute is missing in element under its
    key there is None):
        {
            "id": <id of permission element>,
            "description": <permission description>,
            "kind": <read|write|deny>,
            "xpath": <xpath string>,
            "reference": <cib element id>,
            "object-type": <>,
            "attribute": <>,
        }

    role_el -- acl_role etree element of which permissions would be returned
    """
    return [
        {
            key: permission.get(key)
            for key in [
                "id",
                "description",
                "kind",
                "xpath",
                "reference",
                "object-type",
                "attribute",
            ]
        }
        for permission in role_el.findall("./acl_permission")
    ]


def get_target_list(acl_section):
    """
    Returns list of acl_target elements in format:
        {
            "id": <target id>,
            "role_list": [<assign role_id as string>, ...]
        }

    acl_section -- etree node
    """
    return get_target_like_list(acl_section, TAG_TARGET)


def get_group_list(acl_section):
    """
    Returns list of acl_group elements in format:
        {
            "id": <group id>,
            "role_list": [<assign role_id as string>, ...]
        }

    acl_section -- etree node
    """
    return get_target_like_list(acl_section, TAG_GROUP)


def get_target_like_list(acl_section, tag):
    return [
        {
            "id": target_el.get("id"),
            "role_list": _get_role_list_of_target(target_el),
        }
        for target_el in acl_section.xpath(
            "./*[local-name()=$tag_name]", tag_name=tag
        )
    ]


def _get_role_list_of_target(target):
    """
    Returns all roles assigned to target element as list of strings.

    target -- etree acl_target/acl_group element of which roles should be
        returned
    """
    return [
        role.get("id") for role in target.findall("./role") if role.get("id")
    ]


def remove_permissions_referencing(tree, reference):
    """
    Removes all permission with specified reference.

    tree -- etree node
    reference -- reference identifier
    """
    for permission in tree.xpath(
        ".//acl_permission[@reference=$reference]", reference=reference
    ):
        permission.getparent().remove(permission)
