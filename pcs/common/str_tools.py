import contextlib
from collections.abc import Iterable as IterableAbc
from collections.abc import Sized
from typing import (
    Any,
    Mapping,
    Optional,
    Sequence,
    TypeVar,
    Union,
)

from pcs.common.types import (
    StringIterable,
    StringSequence,
)


def indent(line_list: StringIterable, indent_step: int = 2) -> list[str]:
    """
    return line list where each line of input is prefixed by N spaces

    line_list -- original lines
    indent_step -- count of spaces for line prefix
    """
    return [
        "{0}{1}".format(" " * indent_step, line) if line else line
        for line in line_list
    ]


def outdent(line_list: StringSequence) -> list[str]:
    if not line_list:
        return []
    smallest_indentation = min(
        len(line) - len(line.lstrip(" ")) for line in line_list if line
    )
    return [line[smallest_indentation:] for line in line_list]


def format_list_base(item_list: StringIterable, separator: str = ", ") -> str:
    return separator.join(item_list)


def format_list_dont_sort(
    item_list: StringIterable,
    separator: str = ", ",
) -> str:
    return format_list_base(quote_items(item_list), separator)


def format_list(item_list: StringIterable, separator: str = ", ") -> str:
    return format_list_dont_sort(sorted(item_list), separator)


def format_list_custom_last_separator(
    item_list: StringIterable,
    last_separator: str,
    separator: str = ", ",
) -> str:
    return format_list_custom_last_separator_dont_sort(
        quote_items(sorted(item_list)), last_separator, separator
    )


def format_list_custom_last_separator_dont_sort(
    item_list: StringSequence,
    last_separator: str,
    separator: str = ", ",
) -> str:
    if len(item_list) < 2:
        return format_list_base(item_list)
    return format_list_base(
        [
            format_list_base(item_list[:-1], separator=separator),
            format_list_base(item_list[-1:]),
        ],
        separator=last_separator,
    )


def quote_items(item_list: StringIterable) -> list[str]:
    return [f"'{item}'" for item in item_list]


# For now, tuple[str, str] is sufficient. Feel free to change it if needed,
# e.g. when values can be integers.
def format_name_value_list(item_list: Sequence[tuple[str, str]]) -> list[str]:
    """
    Turn 2-tuples to 'name=value' strings with standard quoting
    """
    output = []
    for raw_name, raw_value in item_list:
        name = quote(raw_name, "= ")
        value = quote(raw_value, "= ")
        output.append(f"{name}={value}")
    return output


# For now, tuple[str, str, str] is sufficient. Feel free to change it if
# needed, e.g. when values can be integers.
def format_name_value_id_list(
    item_list: Sequence[tuple[str, str, str]],
) -> list[str]:
    """
    Turn 3-tuples to 'name=value (id: id))' strings with standard quoting
    """
    output = []
    for raw_name, raw_value, an_id in item_list:
        name = quote(raw_name, "= ")
        value = quote(raw_value, "= ")
        output.append(f"{name}={value} (id: {an_id})")
    return output


def pairs_to_text(pairs: Sequence[tuple[str, str]]) -> list[str]:
    if pairs:
        return [" ".join(format_name_value_list(pairs))]
    return []


def format_name_value_default_list(
    item_list: Sequence[tuple[str, str, bool]],
) -> list[str]:
    """
    Turn 3-tuples to 'name=value' or 'name=value (default)' strings with
    standard quoting
    """
    output = []
    for raw_name, raw_value, is_default in item_list:
        name = quote(raw_name, "= ")
        value = quote(raw_value, "= ")
        default = " (default)" if is_default else ""
        output.append(f"{name}={value}{default}")
    return output


def quote(string: str, chars_to_quote: str) -> str:
    """
    Quote a string if it contains specified characters

    string -- the string to be processed
    chars_to_quote -- the characters causing quoting
    """
    if not frozenset(chars_to_quote) & frozenset(string):
        return string
    if '"' not in string:
        return f'"{string}"'
    if "'" not in string:
        return f"'{string}'"
    return '"{string}"'.format(string=string.replace('"', '\\"'))


def join_multilines(strings: StringSequence) -> str:
    return "\n".join([a.strip() for a in strings if a.strip()])


def split_multiline(string: str) -> list[str]:
    return [
        line for line in [line.strip() for line in string.splitlines()] if line
    ]


def format_optional(
    value: Any,
    template: str = "{} ",
    empty_case: str = "",
) -> str:
    # Number 0 is considered False which does not suit our needs so we check
    # for it explicitly. Beware that False == 0 is true, so we must have an
    # additional check for that (bool is a subclass of int).
    if value or (
        isinstance(value, int) and not isinstance(value, bool) and value == 0
    ):
        return template.format(value)
    return empty_case


def _is_multiple(what: Union[int, Sized]) -> bool:
    """
    Return True if 'what' does not mean one item, False otherwise

    what -- this will be counted
    """
    retval = False
    if isinstance(what, int):
        retval = abs(what) != 1
    elif not isinstance(what, str):
        with contextlib.suppress(TypeError):
            retval = len(what) != 1
    return retval


def _add_s(word: str) -> str:
    """
    add "s" or "es" to the word based on its ending

    word -- word where "s" or "es" should be added
    """
    if word[-1:] in ("s", "x", "o") or word[-2:] in ("ss", "sh", "ch"):
        return word + "es"
    return word + "s"


def get_plural(singular: str) -> str:
    """
    Take singular word form and return plural.

    singular -- singular word (like: is, do, node)
    """
    common_plurals = {
        "is": "are",
        "has": "have",
        "does": "do",
        "it": "they",
        "property": "properties",
    }
    if singular in common_plurals:
        return common_plurals[singular]
    return _add_s(singular)


def format_plural(
    depends_on: Union[int, Sized],
    singular: str,
    plural: Optional[str] = None,
) -> str:
    """
    Takes the singular word form and returns its plural form if depends_on
    is not equal to one/contains one item

    depends_on -- if number (of items) isn't equal to one, return plural
    singular -- singular word (like: is, do, node)
    plural -- optional irregular plural form
    """
    if not _is_multiple(depends_on):
        return singular
    if plural:
        return plural
    return get_plural(singular)


T = TypeVar("T")


def transform(items: list[T], mapping: Mapping[T, str]) -> list[str]:
    return [mapping.get(item, str(item)) for item in items]


def is_iterable_not_str(value: Union[IterableAbc, str]) -> bool:
    return isinstance(value, IterableAbc) and not isinstance(value, str)
