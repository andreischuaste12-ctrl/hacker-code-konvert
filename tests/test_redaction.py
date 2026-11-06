from hacker_code_konvert.redaction import REDACTED, redact, redact_text


def test_redacts_common_secret_shapes() -> None:
    value = "api_key=hck_test_secret_DO_NOT_USE Authorization: Bearer abc.def.ghi"
    redacted = redact_text(value)
    assert "hck_test_secret_DO_NOT_USE" not in redacted
    assert "abc.def.ghi" not in redacted
    assert redacted.count(REDACTED) == 2


def test_redacts_nested_structures() -> None:
    value = {"log": ["password=synthetic-password", {"token": "safe-description"}]}
    redacted = redact(value)
    assert "synthetic-password" not in str(redacted)
