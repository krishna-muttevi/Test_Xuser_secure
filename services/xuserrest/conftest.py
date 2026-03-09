import random
import string

import pytest
from common.base_config import get_base_url
import requests


@pytest.fixture()
def all_users(ranger_config):

    url = f"{ranger_config['base_url']}/xusers/users/"
    
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

    url = f"{ranger_config['base_url']}/xusers/users/"
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

@pytest.fixture(scope="session")
def client_roles(ranger_config):

    username = ranger_config["auth"][0]

    url = f"{ranger_config['base_url']}/xusers/users/userName/{username}"

    response = requests.get(
        url,
        auth=ranger_config["auth"],
        headers=ranger_config["headers"]
    )

    assert response.status_code == 200, \
        f"Failed to fetch user details for {username}"

    return response.json().get("userRoleList", [])



@pytest.fixture()
def get_user_by_id(ranger_config):

    def _get_user(user_id):
        response = requests.get(
            f"{ranger_config['base_url']}/xusers/secure/users/{user_id}",
            auth=ranger_config["auth"],
            headers=ranger_config["headers"]
        )

        if response.status_code == 200:
            return response.json()
        elif response.status_code in [400, 404]:
            return None
        else:
            pytest.fail(
                f"Unexpected response: {response.status_code} - {response.text}"
            )

    return _get_user

@pytest.fixture()
def temp_secure_user(ranger_config, client_roles):

    if "ROLE_SYS_ADMIN" not in client_roles:
        pytest.fail("Admin privileges required to create secure user")

    created_user_ids = []

    def _create_user(role_list = None):

         
        random_suffix = ''.join(random.choices(string.ascii_lowercase, k=5))
        username = f"pytest_fixture_{random_suffix}"

        role_map = {
            "user": "ROLE_USER",
            "admin": "ROLE_SYS_ADMIN",
            "auditor": "ROLE_ADMIN_AUDITOR"
        }

        if role_list:
            unique_roles = {role_map.get(role.lower(), "ROLE_USER") for role in role_list}
        else:
            unique_roles = {"ROLE_USER"}

        final_role_list = list(unique_roles)

        payload = {
            "name": username,
            "firstName": "Fixture",
            "lastName": "User",
            "emailAddress": f"{username}@test.com",
            "password": "Test@123",
            "status": 1,
            "isVisible": 1,
            "userRoleList": final_role_list,
            "groupIdList": [],
            "groupNameList": []
        }
 
        response = requests.post(
            f"{ranger_config['base_url']}/xusers/secure/users",
            json=payload,
            auth=ranger_config["auth"],
            headers=ranger_config["headers"]
            )

        assert response.status_code == 200, f"User creation failed: {response.text}"

        created_user = response.json()
        created_user_ids.append(created_user["id"])

        print(f"\n[Fixture] Created user ID: {created_user['id']}, Roles: {final_role_list}")

        return created_user, created_user["id"]

    yield _create_user

    for user_id in created_user_ids:
        print(f"[Fixture] Cleaning up user ID: {user_id}")

        response = requests.delete(
        f"{ranger_config['base_url']}/xusers/secure/users/{user_id}",
        auth=ranger_config["auth"],
        headers=ranger_config["headers"]
        )

        if response.status_code in [200, 204]:
            print(f"[Fixture] Deleted user ID: {user_id}")

        elif response.status_code in [400, 404]:
            print(f"[Fixture] User ID {user_id} already deleted")

        else:
            pytest.fail(
                f"Unexpected error deleting user ID {user_id}: {response.text}"
            )

@pytest.fixture()
def temp_keyadmin_user(ranger_config, client_roles):

    if "ROLE_SYS_ADMIN" not in client_roles:
        pytest.fail("Admin privileges required to create secure user")

    created_user_id = None
    username = None

    random_suffix = ''.join(random.choices(string.ascii_lowercase, k=5))
    username = f"pytest_keyadmin_{random_suffix}"

    payload = {
        "name": username,
        "firstName": "Fixture",
        "lastName": "KeyAdmin",
        "emailAddress": f"{username}@test.com",
        "password": "Test@123",
        "status": 1,
        "isVisible": 1,
        "userRoleList": ["ROLE_USER"],
        "groupIdList": [],
        "groupNameList": []
    }

    response = requests.post(
        f"{ranger_config['base_url']}/xusers/secure/users",
        json=payload,
        auth=ranger_config["auth"],
        headers=ranger_config["headers"]
    )

    assert response.status_code == 200, f"User creation failed: {response.text}"

    created_user = response.json()
    created_user_id = created_user["id"]

    print(f"\n[Fixture] Created base user: {username} (ID: {created_user_id})")

    role_payload = {
        "vXStrings": [
            {"value": "ROLE_KEY_ADMIN"}
        ]
    }

    response = requests.put(
        f"{ranger_config['base_url']}/xusers/secure/users/roles/{created_user_id}",
        json=role_payload,
        auth=("keyadmin", "rangerR0cks!"),
        headers={**ranger_config["headers"], "X-Requested-By": "ranger"}
    )

    assert response.status_code == 200, f"Keyadmin role update failed: {response.text}"

    print(f"[Fixture] Promoted user → ROLE_KEY_ADMIN")

    yield (created_user, created_user_id)

    print(f"[Fixture] Reverting and deleting user {created_user_id}")

    revert_payload = {
        "vXStrings": [
            {"value": "ROLE_USER"}
        ]
    }

    # revert role
    requests.put(
        f"{ranger_config['base_url']}/xusers/secure/users/roles/{created_user_id}",
        json=revert_payload,
        auth=("keyadmin", "rangerR0cks!"),
        headers={**ranger_config["headers"], "X-Requested-By": "ranger"}
    )

    # delete user
    response = requests.delete(
        f"{ranger_config['base_url']}/xusers/secure/users/{created_user_id}",
        auth=ranger_config["auth"],
        headers=ranger_config["headers"]
    )

    if response.status_code in [200, 204]:
        print(f"[Fixture] Deleted user {created_user_id}")
    elif response.status_code in [400, 404]:
        print(f"[Fixture] User already deleted")
    else:
        pytest.fail(f"Unexpected delete failure: {response.text}")

    

        
