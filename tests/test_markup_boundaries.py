"""Nearby escape calls cannot sanitize a different HTML construction statement."""

from types import SimpleNamespace

from howlproof.evaluators.markup import _unescaped_sinks

CONFIG = SimpleNamespace(sink_functions=["setHTML", "innerHTML"], escape_functions=["esc"])


def test_unrelated_escape_after_unsafe_sink_does_not_hide_defect():
    source = 'setHTML("<b>" + user + "</b>");\nconst other = esc(otherInput);'
    assert len(_unescaped_sinks("view.js", source, CONFIG)) == 1


def test_unrelated_markup_after_plain_sink_does_not_create_defect():
    source = 'setHTML("static text");\nconst other = "<b>" + user + "</b>";'
    assert _unescaped_sinks("view.js", source, CONFIG) == []


def test_semicolon_inside_literal_does_not_truncate_expression():
    source = 'setHTML("<b>prefix;" + user + "</b>");'
    assert len(_unescaped_sinks("view.js", source, CONFIG)) == 1


def test_escaped_sink_is_clean():
    source = 'setHTML("<b>" + esc(user) + "</b>");'
    assert _unescaped_sinks("view.js", source, CONFIG) == []


def test_assignment_ignores_later_escape_statement():
    source = 'element.innerHTML = "<b>" + user + "</b>";\nconst other = esc(otherInput);'
    assert len(_unescaped_sinks("view.js", source, CONFIG)) == 1


def test_quoted_escaped_quote_does_not_end_literal():
    source = 'setHTML("<b>quoted\\";" + user + "</b>");'
    assert len(_unescaped_sinks("view.js", source, CONFIG)) == 1
