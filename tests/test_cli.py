from typer.testing import CliRunner

from ghostrules import __version__
from ghostrules.cli import app

runner = CliRunner()


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == f"ghostrules {__version__}"
