import pytest
import requests


@pytest.fixture(scope="session")
def credentials():
    return ("admin","rangerR0cks!")


@pytest.fixture(scope="session")
def default_headers():
    return {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

@pytest.fixture(scope="session")
def keyadmin_credentials():
    return ("keyadmin", "rangerR0cks!")











