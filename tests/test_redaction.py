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


import time  # noqa: E402

import pytest  # noqa: E402


@pytest.mark.parametrize(
    "value, secret",
    [
        ('{"password": "hunter2-synthetic"}', "hunter2-synthetic"),
        ("token: 'abc123synthetic'", "abc123synthetic"),
        ("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYSYNTHETICKEY", "wJalrXUtnFEMI"),
        ("github_pat_11AAAAAAA0synthetic1234567890abcdefghij", "github_pat_11AAAAAAA0"),
        ("sk_live_" + "x" * 24, "sk_live_xxxx"),
        ("xoxb-1234567890-abcdefghijkl", "xoxb-1234567890"),
        ("postgres://admin:s3cretSYNTH@db.internal/app", "s3cretSYNTH"),
        ('"Authorization": "Bearer abc.def.ghi1234"', "abc.def.ghi1234"),
        (
            "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34Gk\n-----END RSA PRIVATE KEY-----",
            "MIIBOgIBAAJBAKj34Gk",
        ),
        ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N", "eyJhbGciOiJIUzI1NiJ9"),
    ],
)
def test_additional_secret_shapes_are_redacted(value: str, secret: str) -> None:
    redacted = redact_text(value)
    assert secret not in redacted
    assert REDACTED in redacted


def test_ordinary_prose_is_not_redacted() -> None:
    sentence = "the token bucket algorithm is described in section 3"
    assert redact_text(sentence) == sentence


def test_hostile_large_inputs_cannot_cause_catastrophic_backtracking() -> None:
    size = 32_768
    hostile = [
        "a-" * 2_500_000,
        "eyJ" * (size // 3),
        "token=" * (size // 6),
        "password " * (size // 9),
        "-----BEGIN PRIVATE KEY-----" * (size // 27),
        "bearer " * (size // 7),
        'authorization: "bearer ' * (size // 24),
    ]
    started = time.perf_counter()
    for payload in hostile:
        redact_text(payload)
    assert time.perf_counter() - started < 5.0


def test_oversized_text_is_truncated_and_marked() -> None:
    result = redact_text("x" * 100_000)
    assert result.endswith("[TRUNCATED]")
    assert len(result) < 40_000
