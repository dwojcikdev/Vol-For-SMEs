import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--run-integration",
        action="store_true",
        default=False,
        help="run integration tests that execute real Volatility commands",
    )


def pytest_collection_modifyitems(config, items):
    if config.getoption("--run-integration"):
        return

    skip_integration = pytest.mark.skip(
        reason="integration test; run with --run-integration"
    )
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_integration)
