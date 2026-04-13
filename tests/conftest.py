"""Pytest configuration for pgloglens tests."""

import pytest


def pytest_addoption(parser):
    """Add custom command line options."""
    parser.addoption(
        "--docker",
        action="store_true",
        default=False,
        help="Run Docker integration tests (requires Docker)",
    )
    parser.addoption(
        "--slow",
        action="store_true",
        default=False,
        help="Run slow tests",
    )


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "integration: mark test as integration test (requires Docker)"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )


def pytest_collection_modifyitems(config, items):
    """Skip integration tests unless --docker flag is provided."""
    if not config.getoption("--docker"):
        skip_integration = pytest.mark.skip(
            reason="Need --docker option to run integration tests"
        )
        for item in items:
            if "integration" in item.keywords:
                item.add_marker(skip_integration)

    if not config.getoption("--slow"):
        skip_slow = pytest.mark.skip(reason="Need --slow option to run slow tests")
        for item in items:
            if "slow" in item.keywords:
                item.add_marker(skip_slow)
