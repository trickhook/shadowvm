import pytest


def pytest_collection_modifyitems(config, items):
    for item in items:
        if "asyncio" not in item.keywords:
            item.add_marker(pytest.mark.asyncio)
