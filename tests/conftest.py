import pytest

from audit.controls import Evidence, run_all

pytest_plugins = ["results_plugin"]


@pytest.fixture(scope="session")
def ev():
    return Evidence.load()


@pytest.fixture(scope="session")
def results(ev):
    return run_all(ev)
