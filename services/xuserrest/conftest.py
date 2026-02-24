import pytest
from common.base_config import get_base_url
import requests


@pytest.fixture(scope="session")
def ranger_config(credentials, default_headers):
    config = {
        #"base_url": get_base_url("xuserrest"),
        "base_url":"http://localhost:6080/service/xusers",
        "auth": credentials,
        "headers": default_headers
    }

    print("BASE URL:", config["base_url"])

    return config


@pytest.fixture()
def all_users(ranger_config):

    url = f"http://localhost:6080/service/xusers/users/"
    
    response = requests.get(
        url,
        auth=ranger_config["auth"],
        headers=ranger_config["headers"]
    )

    assert response.status_code == 200, f"Failed to fetch users list: {response.status_code}"

    data = response.json()
    assert "vXUsers" in data, "Invalid users list schema"

    users = data["vXUsers"]
    assert isinstance(users, list)
    assert len(users) > 0, "No users found in Ranger"

    return users


@pytest.fixture()
def all_schema_following_users(ranger_config):

    url = "http://localhost:6080/service/xusers/users/"
    response = requests.get(
        url,
        auth=ranger_config["auth"],
        headers=ranger_config["headers"]
    )

    assert response.status_code == 200, f"Failed to fetch users list: {response.status_code}"

    data = response.json()
    users = data["vXUsers"]

    return [
        user for user in users
        if not (7 <= user["id"] <= 18)
    ]