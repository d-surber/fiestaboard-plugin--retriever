"""
The cases of the system check: what the misbehaving server does in each, the
value rows the plugin is given, and what is then asked of FiestaBoard.

A case is one fetch. Its probes are templates rendered after that fetch; in a
probe, and nowhere else, "%" stands for the plugin instance's name and the
dot after it, so that "{{%error}}" is the instance's ``error`` variable.

See README.md beside this file for what the check is for and how to run it.
"""

from dataclasses import dataclass, field
from typing import Any

# A value row as (name, definition, default).
Row = tuple[str, str, str]


@dataclass(frozen=True)
class Case:
    """
    One fetch from the misbehaving server, and what to look at afterwards.

    Attributes:
        name: What the case is about; also how its expected results are filed.
        scenario: What the server does: its steps for each endpoint path, as
            misbehaving_server.py describes them.
        rows: The value rows the instance is given for the fetch. They must
            be ones FiestaBoard will save.
        probes: Templates to render after the fetch.
        refused_rows: Sets of rows that FiestaBoard should refuse to save,
            each with a label. They are tried first and change nothing.
        seconds_to_wait_after: Time to let pass before the next case, for a
            case that leaves a fetch still running.
    """

    name: str
    scenario: dict[str, Any] = field(default_factory=dict)
    rows: list[Row] = field(default_factory=list)
    probes: list[str] = field(default_factory=list)
    refused_rows: list[tuple[str, list[Row]]] = field(default_factory=list)
    seconds_to_wait_after: float = 0


def entry(data: Any, error: str = "") -> dict[str, Any]:
    """A source's entry in a retrieve response."""
    return {"error": error, "data": data}


def answering(data: Any, **step: Any) -> list[dict[str, Any]]:
    """The steps of an endpoint that always answers with this data, and whatever else the step sets."""
    return [{"data": data, **step}]


# The air-quality thresholds of a real page, which name a colour for a reading `p`.
COLOUR_FOR_READING = 'p<=9,"green",p<=35.4,"yellow",p<=55.4,"orange",p<=125.4,"red",p<=225.4,"violet","white"'
SOURCE_DATA = "retriever.s.data"
A_DEFAULT = answering({"a": {"default": "dflt-a"}})
FRESH = answering({"a": entry("fresh")})
ODD_READINGS = [float("nan"), float("inf"), float("-inf"), -0.0, 1e308, 10**40, True, False, None, "41.7", "", -5, [1], {}, "abc", " 12 "]
READING = f"{SOURCE_DATA}.readings[x]"
DEEP_BRACKETS = "(" * 250 + "1" + ")" * 250

# --- Data a well-behaved server would not send, and what rows make of it ------

AWKWARD_VALUES = [
    Case(
        "sources that are not an error and data",
        {
            "/config": answering({"s1": {"type": "string"}}),
            "/retrieve": answering({"s1": "just text", "s2": [1, 2], "s3": None, "s4": 7, "s5": {"data": {"a": 1}}, "s6": {"error": {"code": 5}, "data": [{"t": "x"}]}, "s7": entry(None)}),
        },
        [("p1", "retriever.s1", ""), ("p3", "retriever.s3", "dflt"), ("s2.extra", '"added"', ""), ("l[x]", "retriever.s2[x]*2", ""),
         ("m[x].t", "UPPER(retriever.s6.data[x].t)", ""), ("e6", "retriever.s6.error.code+1", ""), ("n7", "retriever.s7.data", "dflt"), ("n7b", "retriever.s7.data.x", "dflt")],
        ["s1=[{{%s1}}] p1=[{{%p1}}]", "s2=[{{%s2}}] s2.0=[{{%s2.0}}] extra=[{{%s2.extra}}]", "s3=[{{%s3}}] p3=[{{%p3}}] s4=[{{%s4}}]",
         "s5.error=[{{%s5.error}}] s5.data.a=[{{%s5.data.a}}]", "s6.error=[{{%s6.error}}] e6=[{{%e6}}]", 'l=[{{= JOIN(%l, ",") }}] m=[{{%m.0.t}}]',
         "n7=[{{%n7}}] n7b=[{{%n7b}}] s7.data=[{{%s7.data}}]"],
    ),
    Case(
        "sources with the plugin's own names",
        {"/retrieve": answering({"error": entry("SRC-ERROR"), "server": entry("SRC-SERVER"), "a": entry("fresh")})},
        [("got", "retriever.a.data", "none")],
        ["server.name=[{{%server.name}}] a=[{{%a.data}}] got=[{{%got}}]"],
        refused_rows=[("a field added to the error text", [("error.code", '"E1"', "")]), ("a field added to the server's name", [("server.name.x", '"p"', "")])],
    ),
    Case(
        "awkward source and field names",
        {"/retrieve": answering({"": entry("empty"), "a.b": entry("dotted"), "has space": entry("spaced"), "UP": entry({"Key": "upper", "key": "lower"}), "0": entry("zero"),
                                 "x:y": entry("colon"), "ünï": entry({"ké": "uni"}), "if": entry("kw"), "count": entry([1, 2, 3]),
                                 "k": entry({"due-date": "hy", "0": "zero-key", "true": "t", "a b": "sp", "due": 9, "date": 4})})},
        [("r_up", "retriever.UP.data.Key", "none"), ("r_up2", "retriever.up.data.key", "none"), ("r_up3", "UPPER(retriever.up.data.Key)", "none"), ("r_0", "retriever.0.data", "none"),
         ("r_uni", "retriever.ünï.data.ké", "none"), ("r_uni2", 'retriever.ünï.data.ké & "!"', "none"), ("r_if", 'retriever.if.data & "!"', "none"),
         ("r_cnt", "COUNT(retriever.count.data)", "none"), ("r_hy", "retriever.k.data.due-date", "none"), ("r_k0", "retriever.k.data.0", "none"), ("r_true", 'retriever.k.data.true & ""', "none")],
        ["Key=[{{%UP.data.Key}}] key=[{{%up.data.key}}] f=[{{= %UP.data.Key }}]", "0=[{{%0.data}}] colon=[{{%x:y.data}}] sp=[{{%has space.data}}]",
         "dot=[{{%a.b.data}}] empty=[{{%.data}}] uni=[{{%ünï.data.ké}}]", "hy=[{{%k.data.due-date}}] k0=[{{%k.data.0}}] asp=[{{%k.data.a b}}]",
         "up=[{{%r_up}}] up2=[{{%r_up2}}] up3=[{{%r_up3}}] r0=[{{%r_0}}]", "uni=[{{%r_uni}}] uni2=[{{%r_uni2}}] if=[{{%r_if}}] cnt=[{{%r_cnt}}]",
         "hy=[{{%r_hy}}] k0=[{{%r_k0}}] true=[{{%r_true}}]"],
        refused_rows=[("a name with an accent", [("ünï.x", '"1"', "")]), ("a name with a space", [("a b", '"1"', "")])],
    ),
    Case(
        "numbers and non-numbers through a page's colour thresholds",
        {"/retrieve": answering({"s": entry({"pt": 0.1 + 0.2, "readings": ODD_READINGS})})},
        [("c[x].col", f"LET(p,{READING},IFS({COLOUR_FOR_READING}))", "ERR"), ("c[x].raw", READING, ""), ("c[x].plus", READING + "+1", "ERR"), ("c[x].txt", f'"<" & {READING} & ">"', "ERR")],
        ['{{= JOIN(%c, " ", "col") }}', '{{= JOIN(%c, " ", "raw") }}', '{{= JOIN(%c, " ", "plus") }}', '{{= JOIN(%c, " ", "txt") }}',
         "nan=[{{%c.0.raw}}] big=[{{%c.5.raw}}] null=[{{%c.8.raw}}] T=[{{%c.6.raw}}]", "f=[{{= %c.5.raw + 1 }}] pt=[{{%s.data.pt}}] fpt=[{{= %s.data.pt * 10 }}]"],
    ),
    Case(
        "text from the server that looks like markup",
        {"/retrieve": answering({"s": entry({"tpl": "{{= 2 + 3 }}", "frm": "{{= 1/0 }}", "col": "{red}{63}", "ref": "#REF", "qqq": "???", "nl": "line1\nline2", "tab": "a\tb",
                                             "emoji": "hi \U0001f600 ñ ß", "long": {"generate": "text", "size": 5000}, "ctl": "a\u0000b\u001b[31m",
                                             "quote": "say \"hi\" & 'bye'", "brace": "}} {{"})})},
        [("t_tpl", f"{SOURCE_DATA}.tpl", ""), ("t_tpl2", f"LOWER({SOURCE_DATA}.tpl)", ""), ("t_ref", f"{SOURCE_DATA}.ref", "dflt"), ("t_ref2", f'{SOURCE_DATA}.ref & ""', "dflt"),
         ("t_qqq", f'{SOURCE_DATA}.qqq & ""', "dflt"), ("t_len", f"LEN({SOURCE_DATA}.long)", ""), ("t_nl", f'{SOURCE_DATA}.nl & ""', ""), ("t_q", f'{SOURCE_DATA}.quote & ""', "")],
        ["tpl=[{{%s.data.tpl}}] row=[{{%t_tpl}}] row2=[{{%t_tpl2}}]", "frm=[{{%s.data.frm}}]", "f=[{{= %s.data.tpl }}] f2=[{{= %s.data.frm }}]", "col=[{{%s.data.col}}]",
         "ref=[{{%s.data.ref}}] row=[{{%t_ref}}] row2=[{{%t_ref2}}] qqq=[{{%t_qqq}}]", "nl=[{{%s.data.nl}}] row=[{{%t_nl}}] tab=[{{%s.data.tab}}]",
         "emoji=[{{%s.data.emoji}}] ctl=[{{%s.data.ctl}}] len={{= LEN(%s.data.ctl) }}", "q=[{{%s.data.quote}}] row=[{{%t_q}}] brace=[{{%s.data.brace}}]", "len=[{{%t_len}}] long=[{{%s.data.long}}]"],
    ),
    Case(
        "lists whose elements are not what a row expects",
        {"/retrieve": answering({"s": entry({"mix": [{"t": "a", "parts": [1, 2]}, "str", None, [9, 8], 5, {"t": "f", "parts": "notalist"}, {"parts": {"k": 1}}, {"t": None}],
                                             "grid": [[1, 2, 3], [4], [], "xy", None, {"0": "z"}], "short": [1, 2], "longer": [1, 2, 3, 4], "notlist": "abcdef",
                                             "obj": {"0": "a", "1": "b"}, "empty": []})})},
        [("m[x].t", f"{SOURCE_DATA}.mix[x].t", "-"), ("m[x].u", f"UPPER({SOURCE_DATA}.mix[x].t)", "-"), ("m[x].p[y]", f"{SOURCE_DATA}.mix[x].parts[y]", ""),
         ("g[x][y]", f"{SOURCE_DATA}.grid[x][y]", ""), ("two[x]", f"{SOURCE_DATA}.short[x] & {SOURCE_DATA}.longer[x]", ""), ("ch[x]", f"{SOURCE_DATA}.notlist[x]", ""),
         ("ob[x]", f"{SOURCE_DATA}.obj[x]", ""), ("em[x].a", f"{SOURCE_DATA}.empty[x]", ""), ("em[x].b", "x+1", ""), ("gone[x]", f"{SOURCE_DATA}.nothere[x]", "dflt")],
        ['n={{= COUNT(%m) }} t=[{{= JOIN(%m, ",", "t") }}] u=[{{= JOIN(%m, ",", "u") }}]', "p0=[{{%m.0.p}}] p5=[{{%m.5.p}}] p1=[{{%m.1.p}}]",
         'g n={{= COUNT(%g) }} g0=[{{%g.0}}] g3=[{{%g.3}}] j0=[{{= JOIN(%g.0, "") }}]', 'two=[{{= JOIN(%two, ",") }}] ch={{= COUNT(%ch) }} ob={{= COUNT(%ob) }}',
         "em={{= COUNT(%em) }} gone={{= COUNT(%gone) }} [{{%gone}}]"],
    ),
    Case(
        "rows that would make an object of a server's text, number or list",
        {"/retrieve": answering({"s": entry({"grid": [[1, 2], [3, 4]], "items": [{"t": "a"}, {"t": "b"}], "names": ["x", "y", "z"], "n": 5}, "src-problem")})},
        [("s.error.detail", '"D"', ""), ("s.data.grid[x].sum", f"{SOURCE_DATA}.grid[x].0+{SOURCE_DATA}.grid[x].1", ""), ("s.data.names[x].len", f"LEN({SOURCE_DATA}.names[x])", ""),
         ("s.data.items[x].t", f"UPPER({SOURCE_DATA}.items[x].t)", ""), ("s.data.n.sub", '"oops"', ""), ("s.data.items[x].k", "x", "")],
        ["s.error=[{{%s.error}}] detail=[{{%s.error.detail}}]", "grid.0.0=[{{%s.data.grid.0.0}}] sum=[{{%s.data.grid.0.sum}}]", "names.0=[{{%s.data.names.0}}] len=[{{%s.data.names.0.len}}]",
         "items.1.t=[{{%s.data.items.1.t}}] k=[{{%s.data.items.1.k}}] n=[{{%s.data.n}}]"],
    ),
    Case(
        "rows that disagree, and names that are also words of the formula language",
        {"/retrieve": answering({"s": entry({"l": [1, 2, 3]})})},
        [("Due", '"upper"', ""), ("due", '"lower"', ""), ("count", '"c"', ""), ("if", '"i"', "")],
        ["Due=[{{%Due}}] due=[{{%due}}] DUE=[{{%DUE}}]", "count=[{{%count}}] if=[{{%if}}] f=[{{= %count & %if }}]"],
        refused_rows=[("one name as a value, an object and a list", [("a", "1", ""), ("a.b", "2", ""), ("a[x]", f"{SOURCE_DATA}.l[x]", "")]),
                      ("a name defined twice", [("a", "1+1", ""), ("a", "2+2", "")]),
                      ("a field that is a value in one row and an object in another", [("o.a", '"1"', ""), ("o.a.b", '"3"', "")]),
                      ("a list of values in one row and of objects in another", [("q[x]", f"{SOURCE_DATA}.l[x]", ""), ("q[x].f", f"{SOURCE_DATA}.l[x]*10", "")])],
    ),
    Case(
        "parameter names that are words of the formula language",
        {"/retrieve": answering({"s": entry({"l": [10, 20, 30]})})},
        [("k1[true]", f"{SOURCE_DATA}.l[true]+true", ""), ("k2[if]", f"{SOURCE_DATA}.l[if]+if", ""), ("k3[let]", f"{SOURCE_DATA}.l[let]+let", ""), ("k4[X].a", f"{SOURCE_DATA}.l[X]", ""),
         ("k4[X].b", "x", ""), ("k4[X].c", "X", ""), ("k5[s]", f"{SOURCE_DATA}.l[s]", ""), ("k8[_]", f"{SOURCE_DATA}.l[_]+_", ""), ("k9[item]", f"{SOURCE_DATA}.l[item]+item", "")],
        ['k1=[{{= JOIN(%k1, ",") }}] k2=[{{= JOIN(%k2, ",") }}] k3=[{{= JOIN(%k3, ",") }}]', "k4.1 a=[{{%k4.1.a}}] b=[{{%k4.1.b}}] c=[{{%k4.1.c}}]",
         'k5=[{{= JOIN(%k5, ",") }}] k8=[{{= JOIN(%k8, ",") }}] k9=[{{= JOIN(%k9, ",") }}]'],
    ),
]

# --- The edges of what is allowed -----------------------------------------------

A_LIST = {"/retrieve": answering({"s": entry({"l": [10, 20, 30, 40]})})}
AN_ODD_CONFIG = answering({
    "a": {"type": "object", "properties": {"n": {"type": "integer"}, "l": {"type": "array"}, "s": {"type": "string", "default": "dflt-s"},
                                           "deep": {"type": "object", "properties": {"z": {"type": "boolean"}}}}},
    "b": {"default": [{"t": "default item"}]}, "c": "not a schema", "d": {"type": ["string", "null"]}, "e": {"type": "object", "properties": "oops"},
    "f": {"type": "object", "default": "wrong type"},
})

LIMITS = [
    Case("an index written in Arabic-Indic digits", A_LIST, [("ar", f"{SOURCE_DATA}.l[٢]", "dflt")], ["ar=[{{%ar}}]"]),
    Case("an index written as a superscript two", A_LIST, [("sup", f"{SOURCE_DATA}.l.²", "dflt"), ("fine", f"{SOURCE_DATA}.l.1", "")],
         ["sup=[{{%sup}}] fine=[{{%fine}}] l.1=[{{%s.data.l.1}}]"]),
    Case("names and formulas at and past the depth allowed", A_LIST, [("a" + ".b" * 32, "1+1", ""), ("p", "(" * 32 + "1" + ")" * 32, "")],
         ["p=[{{%p}}] a.b.b=[{{%a.b.b}}]", "f=[{{= " + DEEP_BRACKETS + " }}]"],
         refused_rows=[("a formula 250 brackets deep", [("deep", DEEP_BRACKETS, "")]), ("a name 600 steps deep", [("a" + ".b" * 600, "1+1", "")])]),
    Case("data nested 500 deep, read only", {"/retrieve": answering({"s": entry({"generate": "nesting", "size": 500})})}, [("plain", f"{SOURCE_DATA}.k.k.k.k", "dflt")],
         ["plain=[{{%plain}}]", "k.k=[{{%s.data.k.k}}]"]),
    Case("data nested 500 deep, with a row that adds to it", {"/retrieve": answering({"s": entry({"generate": "nesting", "size": 500})})}, [("s.x", '"1"', ""), ("plain", "1+1", "")],
         ["x=[{{%s.x}}] plain=[{{%plain}}]"]),
    Case("a retrieve that fails after an odd config: the defaults", {"/config": AN_ODD_CONFIG, "/retrieve": [{"status": [500, "Internal Server Error " + "x" * 100]}]},
         [("first", "retriever.b.data[0].t", "none"), ("items[x].t", "UPPER(retriever.b.data[x].t)", ""), ("n1", "retriever.a.data.n+1", "none"), ("cc", "retriever.c.data", "none")],
         ["n=[{{%a.data.n}}] s=[{{%a.data.s}}] z=[{{%a.data.deep.z}}] l=[{{%a.data.l}}]", "b=[{{%b.data.0.t}}] c=[{{%c.data}}] d=[{{%d.data}}] e=[{{%e.data}}] f=[{{%f.data}}]",
          "first=[{{%first}}] items=[{{%items.0.t}}] n1=[{{%n1}}] cc=[{{%cc}}]", "server.name=[{{%server.name}}]"]),
    Case("the config changes, and the server then speaks no protocol version we do",
         {"/server": [{}, {"data": {"name": "Second", "version": "2", "supported_protocol_version_range": {"min": 2, "max": 9}}}],
          "/config": answering({"a": {"type": "string"}}, config_fingerprint=1), "/retrieve": answering({"a": entry("fresh"), "zz": entry("unlisted")}, config_fingerprint=2)},
         [("up", "UPPER(retriever.zz.data)", "none")], ["a=[{{%a.data}}] zz=[{{%zz.data}}] up=[{{%up}}] server=[{{%server.name}}]"]),
    Case("a fingerprint that never settles, from a slow server: five requests in one fetch",
         {"/server": [{"delay": 0.9}], "/config": [{"delay": 0.9, "config_fingerprint": 1, "data": {"a": {"default": "dflt-a"}}}, {"delay": 0.9, "config_fingerprint": 3}],
          "/retrieve": [{"delay": 0.9, "config_fingerprint": 2, "data": {"a": entry("fresh")}}]},
         [("up", "UPPER(retriever.a.data)", "none")], ["a=[{{%a.data}}] up=[{{%up}}] server=[{{%server.name}}]"]),
] + [
    Case(f"protocol version range: {label}", {"/server": answering({"name": "H", "version": "0", **({} if offered is None else {"supported_protocol_version_range": offered})}),
                                              "/retrieve": answering({"a": entry("got-through")})}, [], ["a=[{{%a.data}}]"])
    for label, offered in [("lowest above highest", {"min": 3, "max": 1}), ("lowest as text", {"min": "1", "max": 1}), ("true and true", {"min": True, "max": True}),
                           ("fractions", {"min": 1.0, "max": 1.0}), ("enormous", {"min": -5, "max": 10**30}), ("a list", [1, 1]), ("missing", None)]
]

# --- Answers that are not the server's answer -----------------------------------

BROKEN_ANSWERS = [
    Case(f"a retrieve answered with {label}", {"/config": A_DEFAULT, "/retrieve": [step]}, [], ["a=[{{%a.data}}]"])
    for label, step in [
        ("another request's ID", {"request_id": "nope"}), ("a fingerprint that is a fraction", {"config_fingerprint": 7.5}), ("a fingerprint of true", {"config_fingerprint": True}),
        ("a fingerprint as text", {"config_fingerprint": "1"}), ("no fingerprint", {"omit": ["config_fingerprint"]}), ("data that is a list", {"data": [1]}),
        ("no data", {"omit": ["data"]}), ("text that is not JSON", {"plain": "not json"}), ("a JSON list", {"plain": "[]"}), ("an empty body", {"raw": "empty"}),
        ("random bytes", {"raw": "random"}), ("a body cut short", {"raw": "cut short"}), ("a body with bytes added", {"raw": "bytes added"}),
        ("a response sealed for /config", {"sealed_for": "/config"}), ("400 Stale Timestamp", {"status": [400, "Stale Timestamp"]}), ("400 and no reason", {"status": [400, ""]}),
        ("204 No Content", {"status": [204, "No Content"]}), ("a redirect a client follows", {"status": [302, "Found"], "location": "/retrieve"}),
        ("a redirect a client does not follow", {"status": [307, "Temporary Redirect"], "location": "/retrieve"}),
        ("a status whose reason has markup in it", {"status": [418, "I'm a teapot {red} {{= 2 + 3 }}"]}), ("nothing", {"close": True}),
    ]
] + [
    Case("server info that is a list", {"/server": answering([1, 2])}),
    Case("every request taking a second and a half", {"/server": [{"delay": 1.5}], "/config": [{"delay": 1.5, "data": {"a": {"default": "dflt-a"}}}],
                                                     "/retrieve": [{"delay": 1.5, "data": {"a": entry("fresh")}}]}, [("up", "UPPER(retriever.a.data)", "none")], ["a=[{{%a.data}}] up=[{{%up}}]"]),
]

# --- Size and time: these say more about the machine than about the code --------

A_FETCH_THAT_WORKS = Case("a fetch that works, in between", {"/config": A_DEFAULT, "/retrieve": FRESH}, [], ["a=[{{%a.data}}]"])
HEAVY = [
    Case("three thousand elements and three formula rows", {"/retrieve": answering({"s": entry({"items": {"generate": "list", "size": 3000}})})},
         [("b[x].label", f'PAD(LEFT(UPPER({SOURCE_DATA}.items[x].title),12),12) & "|"', ""), ("b[x].k", "x+1", ""),
          ("b[x].c", f'IFS({SOURCE_DATA}.items[x].n<=9,"green",{SOURCE_DATA}.items[x].n<=35,"yellow","white")', "")],
         ['n={{= COUNT(%b) }} last=[{{= AT(%b, 2999, "label") }}] c=[{{%b.20.c}}]']),
    A_FETCH_THAT_WORKS,
    Case("two megabytes of text in one value", {"/retrieve": answering({"s": entry({"long": {"generate": "text", "size": 2_000_000}})})}, [("n", f"LEN({SOURCE_DATA}.long)", "")], ["n=[{{%n}}]"]),
    A_FETCH_THAT_WORKS,
    Case("an answer sent a byte every 0.4 s", {"/config": A_DEFAULT, "/retrieve": [{"dribble": [1, 0.4, 12], "data": {"a": entry("fresh")}}]}, [], ["a=[{{%a.data}}]"], seconds_to_wait_after=13),
    A_FETCH_THAT_WORKS,
]

GROUPS = {"values": AWKWARD_VALUES, "limits": LIMITS, "answers": BROKEN_ANSWERS, "heavy": HEAVY}
