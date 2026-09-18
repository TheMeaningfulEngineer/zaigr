"""Account preparation is automatic, not a public CLI workflow."""

from tests.conftest import err_msg, run


def test_account_preparation_has_no_public_command(zaigr_bin, zaigr_home):
    """Users cannot invoke the removed implementation-specific command."""
    stdout, stderr, rc = run(
        [zaigr_bin, "global", "base-image", "match-user"], timeout=10,
    )
    assert rc != 0, err_msg(stdout, stderr)
    assert "unknown command" in stdout + stderr, err_msg(stdout, stderr)


def test_base_image_help_hides_account_preparation(zaigr_bin, zaigr_home):
    """Base-image help contains no ownership workaround to manage."""
    stdout, stderr, rc = run(
        [zaigr_bin, "global", "base-image", "--help"], timeout=10,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert "match-user" not in stdout
    assert "UID" not in stdout
