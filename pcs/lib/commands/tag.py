from contextlib import contextmanager
from typing import (
    Dict,
    Iterable,
    Iterator,
    Sequence,
)
from xml.etree.ElementTree import Element

from pcs.common.reports import SimpleReportProcessor
from pcs.common.tools import Version
from pcs.lib.cib import tag
from pcs.lib.cib.tools import (
    get_resources,
    get_tags,
    IdProvider,
)
from pcs.lib.env import LibraryEnvironment
from pcs.lib.errors import LibraryError
from pcs.lib.xml_tools import get_root


REQUIRED_CIB_VERSION = Version(1, 3, 0)

@contextmanager
def cib_tags_section(env: LibraryEnvironment) -> Iterator[Element]:
    yield get_tags(env.get_cib(REQUIRED_CIB_VERSION))
    env.push_cib()

def create(
    env: LibraryEnvironment,
    tag_id: str,
    idref_list: Sequence[str],
) -> None:
    """
    Create a tag in a cib.

    env -- provides all for communication with externals
    tag_id -- identifier of new tag
    idref_list -- reference ids which we want to tag
    """
    with cib_tags_section(env) as tags_section:
        report_processor = SimpleReportProcessor(env.report_processor)
        report_processor.report_list(
            tag.validate_create_tag(
                get_resources(get_root(tags_section)),
                tag_id,
                idref_list,
                IdProvider(tags_section),
            )
        )
        if report_processor.has_errors:
            raise LibraryError()
        tag.create_tag(tags_section, tag_id, idref_list)

def config(
    env: LibraryEnvironment,
    tag_filter: Sequence[str],
) -> Iterable[Dict[str, Iterable[str]]]:
    """
    Get tags specified in tag_filter or if empty, then get all the tags
    configured.

    env -- provides all for communication with externals
    tag_filter -- list of tags we want to get
    """
    tags_section = get_tags(env.get_cib(REQUIRED_CIB_VERSION))
    report_processor = SimpleReportProcessor(env.report_processor)
    report_processor.report_list(
        tag.validate_tag_ids_exist(tags_section, tag_filter)
    )
    if report_processor.has_errors:
        raise LibraryError()
    return tag.get_list_of_tags(tags_section, tag_filter)
