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

@pytest.fixture(scope="session")
def ranger_config(credentials, default_headers):

    return {
        "base_url": "http://localhost:6080/service",
        "auth": credentials,
        "headers": default_headers
    }

@pytest.fixture(scope="session")
def ranger_key_admin_config(keyadmin_credentials, default_headers):

    return {
        "id" : 3,
        "base_url": "http://localhost:6080/service",
        "auth": keyadmin_credentials,
        "headers": default_headers
    }



