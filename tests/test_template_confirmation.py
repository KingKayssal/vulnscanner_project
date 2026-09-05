from core.template_engine import HTTPResponseLike, LoadedTemplate, evaluate_template


def _template():
    return LoadedTemplate(
        id="xss", name="XSS", severity="high", category="xss", cwe="CWE-79",
        cvss_base_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        description="", remediation="", matcher={"type": "reflected-marker", "requires_confirmation": True}, raw={},
    )


def _response(text, content_type):
    return HTTPResponseLike(
        url="https://example.com/?q=x", status_code=200,
        headers={"content-type": content_type}, text=text,
    )


def test_raw_html_reflection_is_confirmed():
    result = evaluate_template(_template(), _response("<p>sc4n_abc<b></p>", "text/html"), "sc4n_abc<b>")
    assert result.matched is True
    assert result.confirmed is True


def test_script_reflection_is_not_confirmed():
    result = evaluate_template(_template(), _response("<script>const x = 'sc4n_abc<b>';</script>", "text/html"), "sc4n_abc<b>")
    assert result.matched is True
    assert result.confirmed is False


def test_json_reflection_is_not_confirmed():
    result = evaluate_template(_template(), _response('{"q":"sc4n_abc<b>"}', "application/json"), "sc4n_abc<b>")
    assert result.matched is True
    assert result.confirmed is False


def test_html_encoded_reflection_is_not_matched_or_confirmed():
    result = evaluate_template(_template(), _response("&lt;p&gt;sc4n_abc&lt;b&gt;&lt;/p&gt;", "text/html"), "sc4n_abc<b>")
    assert result.matched is False
    assert result.confirmed is False