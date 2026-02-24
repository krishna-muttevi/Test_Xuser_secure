import pytest

@pytest.fixture(scope="session")
def credentials():
    return ("admin", "rangerR0cks!")

@pytest.fixture(scope="session")
def default_headers():
    return {"Accept": "application/json"}