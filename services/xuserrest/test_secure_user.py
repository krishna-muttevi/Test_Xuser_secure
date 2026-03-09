from urllib import response
import pytest
import requests
import json
from datetime import datetime
from common.utils import fetch_logs
import random
import string

# from utils import (
#     assert_response,
#     validate_secure_user_schema,
#     user_exists,
#     delete_user,
#     validate_external_user_schema
# )

BIGINT_MIN = -9223372036854775808
BIGINT_MAX =  9223372036854775807

@pytest.mark.usefixtures("ranger_config", "ranger_key_admin_config")
@pytest.mark.xuserrest
@pytest.mark.secure_endpoint
class TestSecureUserEndpoint:
    SERVICE_NAME = "admin"

    @pytest.fixture(autouse=True)
    def _setup(self, ranger_config, ranger_key_admin_config):
        self.ranger_config = ranger_config
        self.ranger_key_admin_config = ranger_key_admin_config

    def _assert_response(self, response, expected_status):
        
        actual_status = response.status_code

        if isinstance(expected_status, int):
            valid = actual_status == expected_status

        elif isinstance(expected_status, (list, tuple, set)):
            valid = actual_status in expected_status

        else:
            raise TypeError(
                f"expected_status must be int or list/tuple/set, "
                f"got {type(expected_status)}"
            )
        if not valid:
            logs = fetch_logs(self.SERVICE_NAME)
            pytest.fail(
                f"\nExpected: {expected_status}"
            f"\nActual: {actual_status}"
            f"\nResponse: {response.text}"
            f"\nLogs:\n{logs}"
            )


    def _validate_secure_user_schema(self, data):

        assert "id" in data
        assert isinstance(data["id"], int)
        assert BIGINT_MIN <= data["id"] <= BIGINT_MAX

        assert isinstance(data.get("name"), str)
        assert 1 <= len(data["name"]) <= 767

        assert isinstance(data.get("firstName"), str)
        assert len(data["firstName"]) <= 256

        if data.get("emailAddress"):
            assert isinstance(data["emailAddress"], str)
            assert len(data["emailAddress"]) <= 512

        assert data.get("status") in [0, 1]
        assert data.get("isVisible") in [0, 1]

        assert data.get("password") == "*****"

        for field in ["createDate", "updateDate"]:
            if field in data:
                datetime.fromisoformat(
                    data[field].replace("Z", "+00:00")
                )

        # Roles
        roles = data.get("userRoleList")
        assert isinstance(roles, list)
        assert len(roles) > 0

        for role in roles:
            assert isinstance(role, str)
            assert len(role) <= 255

        # Groups
        group_names = data.get("groupNameList", [])
        group_ids = data.get("groupIdList", [])

        for name in group_names:
            assert isinstance(name, str)
            assert len(name) <= 767

        for gid in group_ids:
            assert isinstance(gid, int)
            assert BIGINT_MIN <= gid <= BIGINT_MAX

        assert len(group_names) == len(group_ids), \
            "Mismatch between groupNameList and groupIdList"

        # Sync Source
        sync_source = data.get("syncSource")
        if sync_source:
            assert isinstance(sync_source, str)

        other_attributes = data.get("otherAttributes")
        if other_attributes:
            parsed = json.loads(other_attributes)
            if "sync_source" in parsed and sync_source:
                assert parsed["sync_source"] == sync_source

        # Owner / updatedBy
        for field in ["owner", "updatedBy"]:
            if data.get(field):
                assert isinstance(data[field], str)
                assert len(data[field]) <= 256

    def _user_exists(self, user_id, auth = None,):
        if auth is None:
            auth = self.ranger_config["auth"]
        response = requests.get(
            f"{self.ranger_config['base_url']}/xusers/secure/users/{user_id}",
            auth=auth,
            headers=self.ranger_config["headers"]
        )

        return response.status_code == 200
    
    def _delete_user(self, user_id, force=False):
        query_params = {
            "forceDelete": "true" if force else "false"
        }
        response = requests.delete(
            f"{
                self.ranger_config['base_url']}/xusers/secure/users/{user_id}",
                auth=self.ranger_config["auth"],
                headers={
                    **self.ranger_config["headers"],
                    "X-Requested-By": "ranger"
                },
            params=query_params
        )

        print("DELETE status:", response.status_code)
        print("DELETE body:", response.text)

        return response.status_code in [200, 204]
    
    def _external_user_schema_validation(self, data):
        assert "startIndex" in data and isinstance(data["startIndex"], int)
        assert "pageSize" in data and isinstance(data["pageSize"], int)
        assert "totalCount" in data and isinstance(data["totalCount"], int)
        assert "resultSize" in data and isinstance(data["resultSize"], int)

        assert "vXStrings" in data
        assert isinstance(data["vXStrings"], list)
        assert len(data["vXStrings"]) > 0

        assert "value" in data["vXStrings"][0]
        assert isinstance(data["vXStrings"][0]["value"], str)
        assert len(data["vXStrings"][0]["value"]) <= 255
        assert "queryTimeMS" in data and isinstance(data["queryTimeMS"], int)

    # POSITIVE TESTS
    @pytest.mark.get
    @pytest.mark.positive
    def test_get_secure_user_schema_validation(self, client_roles, all_schema_following_users):

        if client_roles == ["ROLE_USER"]:
            assert False, "Test requires elevated privileges to access all users"
            
        for user in all_schema_following_users:

            response = requests.get(
                f"{self.ranger_config['base_url']}/xusers/secure/users/{user['id']}",
                auth=self.ranger_config["auth"],
                headers=self.ranger_config["headers"]
            )

            self._assert_response(response, 200)

            assert response.headers["Content-Type"].startswith("application/json")
            assert response.elapsed.total_seconds() < 2

            data = response.json()

            self._validate_secure_user_schema(data)

            assert data["id"] == user["id"]
    
    @pytest.mark.get
    @pytest.mark.positive
    @pytest.mark.parametrize("auth_role, target_role", [
        ("admin", "admin"),
        ("admin", "auditor"),
        ("auditor", "admin"),
        ("auditor", "auditor"),
        ("keyadmin", "keyadmin"),
        ("keyadmin", "user"),
        ("s_auditor", "auditor"),

        ])
    def test_get_secure_external_user(self, client_roles, auth_role, target_role, request):

        if not any(r in client_roles for r in ["ROLE_SYS_ADMIN", "ROLE_ADMIN_AUDITOR","ROLE_KEY_ADMIN"]):
            pytest.skip("Test requires admin or auditor privileges")
        if target_role == "keyadmin":
            target_id = self.ranger_key_admin_config["id"]
            assert self._user_exists(target_id, auth=self.ranger_key_admin_config["auth"]), "Pre-requisite failed: Expected keyadmin user does not exist"
        else:    
            target_user, target_id = request.getfixturevalue("temp_secure_user")([target_role])

        if auth_role == "admin":
            authorization = self.ranger_config["auth"]

        elif auth_role == "auditor":
            auth_user, auth_id = request.getfixturevalue("temp_secure_user")(["auditor"])
            authorization = (auth_user["name"], "Test@123")
        elif auth_role == "s_auditor":
            auth_user, auth_id = target_user, target_id
            authorization = (auth_user["name"], "Test@123")
        elif auth_role == "keyadmin":
            authorization = self.ranger_key_admin_config["auth"] 
 

        response = requests.get(
        f"{self.ranger_config['base_url']}/xusers/secure/users/external/{target_id}",
            auth=authorization,
            headers=self.ranger_config["headers"]
        )

        self._assert_response(response, 200)

        data = response.json()

        if auth_role == "admin":
            self._external_user_schema_validation(data)

        elif auth_role == "auditor":
            # If auditor fetching their own data
            if auth_id == target_id:
                self._external_user_schema_validation(data)
            else:
                assert data["vXStrings"] == [], \
                "Auditor should not see other users' external roles"


    @pytest.mark.get
    @pytest.mark.positive
    @pytest.mark.parametrize("auth_role, target_role", [
        ("admin", "admin"),
        ("admin", "auditor"),
        ("keyadmin", "keyadmin"),
        ("keyadmin", "user"),
        ("s_auditor", "auditor"),
        ])
    def test_get_secure_user_roles_by_username(self, client_roles, auth_role, target_role, request): 
        #admin cant access keyadmin, can access the users, auditor, admin
        # keyadmin cant access admin, can access the users, keyadmin
        # auditor if it is with same name and creds it will return this is flaw in internal repo
 
        if not any(r in client_roles for r in ["ROLE_SYS_ADMIN", "ROLE_ADMIN_AUDITOR","ROLE_KEY_ADMIN"]):
            pytest.skip("Test requires admin or auditor privileges")
        if target_role == "keyadmin":
            # cant create keyadmin user, so create an keyadmin manually
            target_user,target_id = request.getfixturevalue("temp_keyadmin_user")
            assert self._user_exists(target_id, auth=self.ranger_key_admin_config["auth"]), "Pre-requisite failed: Expected keyadmin user does not exist"
            target_name = target_user["name"]
        else:    
            target_user, target_id = request.getfixturevalue("temp_secure_user")([target_role])
            target_name = target_user["name"]

        if auth_role == "admin":
            authorization = self.ranger_config["auth"]

        elif auth_role == "auditor":
            auth_user, auth_id = request.getfixturevalue("temp_secure_user")(["auditor"])
            authorization = (auth_user["name"], "Test@123")
        elif auth_role == "s_auditor":
            auth_user, auth_id = target_user, target_id
            authorization = (auth_user["name"], "Test@123")
        elif auth_role == "keyadmin":
            authorization = self.ranger_key_admin_config["auth"] 
        response = requests.get(
            f"{self.ranger_config['base_url']}/xusers/secure/users/roles/userName/{target_name}",
            auth=authorization,
            headers={**self.ranger_config["headers"], "X-Requested-By": "ranger"}
        )
        print("Response text:", response.text, "Response code:", response.status_code, " for auth_role:", auth_role, " target_role:", target_role)

        self._assert_response(response, 200)

        data = response.json()

        if auth_role == "admin":
            self._external_user_schema_validation(data)

        elif auth_role == "auditor":
            # If auditor fetching their own data
            if auth_id == target_id:
                self._external_user_schema_validation(data)
            else:
                assert data["vXStrings"] == [], \
                "Auditor should not see other users' external roles"


    @pytest.mark.post
    @pytest.mark.positive
    def test_create_secure_user(self, client_roles):

        if "ROLE_SYS_ADMIN" not in client_roles:
            assert False, "Test requires admin privileges"

        print("\nCreating a new secure user")

        random_suffix = ''.join(random.choices(string.ascii_lowercase, k=5))
        username = f"pytest_user_{random_suffix}"

        payload = {
            "name": username,
            "firstName": "PyTest",
            "lastName": "User",
            "emailAddress": f"{username}@test.com",
            "password": "Test@123",
            "status": 1,
            "isVisible": 1,
            "userRoleList": ["ROLE_USER"],
            "groupIdList": [],
            "groupNameList": []
        }

        response = requests.post(
            f"{self.ranger_config['base_url']}/xusers/secure/users",
            json=payload,
            auth=self.ranger_config["auth"],
            headers=self.ranger_config["headers"]
        )

        self._assert_response(response, 200)
        data = response.json()
        user_id = data["id"]

        print(f"\nCreated user: {username} | ID: {user_id}")

        try:
            self._validate_secure_user_schema(data)
            assert data["name"] == username
            # Verify persistence
            verify_response = requests.get(
                f"{self.ranger_config['base_url']}/xusers/secure/users/{user_id}",
                auth=self.ranger_config["auth"],
                headers=self.ranger_config["headers"]
            )

            self._assert_response(verify_response, 200)

            verify_data = verify_response.json()
            assert verify_data["id"] == user_id
        finally:
            if user_id:
                self._delete_user(user_id, force=True)

    @pytest.mark.put
    @pytest.mark.positive
    def test_update_secure_user_flow(self, request, client_roles):

        if not any(role in client_roles for role in ["ROLE_SYS_ADMIN", "ROLE_KEY_ADMIN"]):
            assert False, "Test requires admin or key-admin privileges"

        
        created_user, user_id = request.getfixturevalue("temp_secure_user")()
            
        print(f"Created user ID: {user_id}, firstName: {created_user['firstName']}")

        print("\n Updating created user")
        update_payload = created_user.copy()
        update_payload["firstName"] = "Updatedname"

        update_response = requests.put(
            f"{self.ranger_config['base_url']}/xusers/secure/users/{user_id}",
            json=update_payload,
            auth=self.ranger_config["auth"],
            headers=self.ranger_config["headers"]
            )

        self._assert_response(update_response, 200)
        updated_data = update_response.json()

        self._validate_secure_user_schema(updated_data)
        assert updated_data["firstName"] == "Updatedname"

        print(f"Update successful for user ID: {user_id}, firstName: {updated_data['firstName']}")

    @pytest.mark.put
    @pytest.mark.positive
    def test_update_secure_user_active_status(self, request, client_roles):

        if "ROLE_SYS_ADMIN" not in client_roles:
            assert False, "Test requires admin privileges"

        created_user1, user_id1 = request.getfixturevalue("temp_secure_user")()
        created_user2, user_id2 = request.getfixturevalue("temp_secure_user")()

        print(f"\nTesting active status update")

        update_payload = {
                str(user_id1): 0,
                str(user_id2): 0
        }

        response = requests.put(
            f"{self.ranger_config['base_url']}/xusers/secure/users/activestatus",
            json=update_payload,
            auth=(self.ranger_config["auth"]),
            headers={
                **self.ranger_config["headers"],
                "X-Requested-By": "ranger"
            }
        )
        assert response.status_code == 204, f"Failed to update active status: {response.text}"
        response1 = requests.get(
            f"{self.ranger_config['base_url']}/xusers/secure/users/{user_id1}",
            auth=self.ranger_config["auth"],
            headers=self.ranger_config["headers"]
        )
        response2 = requests.get(
            f"{self.ranger_config['base_url']}/xusers/secure/users/{user_id2}",
            auth=self.ranger_config["auth"],
            headers=self.ranger_config["headers"]
        )
        assert response1.json()["status"] == 0, f"User ID {user_id1} active status not updated"
        assert response2.json()["status"] == 0, f"User ID {user_id2} active status not updated"

    @pytest.mark.put
    @pytest.mark.positive
    def test_update_secure_user_visibility(self, request, client_roles):

        if "ROLE_SYS_ADMIN" not in client_roles:
            assert False, "Test requires admin privileges"

        created_user1, user_id1 = request.getfixturevalue("temp_secure_user")()
        created_user2, user_id2 = request.getfixturevalue("temp_secure_user")()

        print(f"\nTesting visibility update")

        update_payload = {
                str(user_id1): 0,
                str(user_id2): 0
        }

        response = requests.put(
            f"{self.ranger_config['base_url']}/xusers/secure/users/visibility",
            json=update_payload,
            auth=(self.ranger_config["auth"]),
            headers={
                **self.ranger_config["headers"],
                "X-Requested-By": "ranger"
            }
        )
        assert response.status_code == 204, f"Failed to update active status: {response.text}"
        response1 = requests.get(
            f"{self.ranger_config['base_url']}/xusers/secure/users/{user_id1}",
            auth=self.ranger_config["auth"],
            headers=self.ranger_config["headers"]
        )
        response2 = requests.get(
            f"{self.ranger_config['base_url']}/xusers/secure/users/{user_id2}",
            auth=self.ranger_config["auth"],
            headers=self.ranger_config["headers"]
        )
        assert response1.json()["isVisible"] == 0, f"User ID {user_id1} visibility not updated"
        assert response2.json()["isVisible"] == 0, f"User ID {user_id2} visibility not updated"

    @pytest.mark.parametrize("auth_role, target_role", [
        ("admin", "admin"),
        ("admin", "auditor"),
        ("admin", "user"),
        ("keyadmin", "keyadmin"),
        ("keyadmin", "user")
        ])
    @pytest.mark.put
    @pytest.mark.positive
    def test_update_secure_role_using_username(self, auth_role, target_role, client_roles, request):

        if not any(role in client_roles for role in ["ROLE_SYS_ADMIN", "ROLE_KEY_ADMIN"]):
            assert False, "Test requires admin or key-admin privileges"

        if target_role == "keyadmin":
            target_user,target_id = request.getfixturevalue("temp_keyadmin_user")
            assert self._user_exists(target_id, auth=self.ranger_key_admin_config["auth"]), "Pre-requisite failed: Expected keyadmin user does not exist"
            
        else:
            target_user, target_id = request.getfixturevalue("temp_secure_user")([target_role])

        if auth_role == "admin":
            authorization = self.ranger_config["auth"]
        elif auth_role == "keyadmin":
            authorization = self.ranger_key_admin_config["auth"]
        else:
            auth_user, auth_id = request.getfixturevalue("temp_secure_user")(["auditor"])
            authorization = (auth_user["name"], "Test@123")
            

        print(f"\nTesting role update for user: {target_user['name']}")

        update_payload = {
            "vXStrings": [
                {"value": "ROLE_USER"}
            ]
        }

        response = requests.put(
            f"{self.ranger_config['base_url']}/xusers/secure/users/roles/userName/{target_user['name']}",
            json=update_payload,
            auth=authorization,
            headers={
                **self.ranger_config["headers"],
                "X-Requested-By": "ranger"
            }
        )

        self._assert_response(response, 200)

        updated_data = response.json()
        self._external_user_schema_validation(updated_data)
        assert "ROLE_USER" in updated_data["vXStrings"][0]["value"]


    @pytest.mark.parametrize("auth_role, target_role", [
        ("admin", "admin"),
        ("admin", "auditor"),
        ("admin", "user"),
        ("keyadmin", "keyadmin"),
        ("keyadmin", "user")
        ])
    @pytest.mark.put
    @pytest.mark.positive
    def test_update_secure_role_using_id(self, auth_role, target_role, client_roles, request):

        if not any(role in client_roles for role in ["ROLE_SYS_ADMIN", "ROLE_KEY_ADMIN"]):
            assert False, "Test requires admin or key-admin privileges"

        if target_role == "keyadmin":
            target_user,target_id = request.getfixturevalue("temp_keyadmin_user")
            assert self._user_exists(target_id, auth=self.ranger_key_admin_config["auth"]), "Pre-requisite failed: Expected keyadmin user does not exist"
            
        else:
            target_user, target_id = request.getfixturevalue("temp_secure_user")([target_role])

        if auth_role == "admin":
            authorization = self.ranger_config["auth"]
        elif auth_role == "keyadmin":
            authorization = self.ranger_key_admin_config["auth"]
        else:
            auth_user, auth_id = request.getfixturevalue("temp_secure_user")(["auditor"])
            authorization = (auth_user["name"], "Test@123")
            

        print(f"\nTesting role update for user: {target_user['name']}")

        update_payload = {
            "vXStrings": [
                {"value": "ROLE_USER"}
            ]
        }

        response = requests.put(
            f"{self.ranger_config['base_url']}/xusers/secure/users/roles/{target_id}",
            json=update_payload,
            auth=authorization,
            headers={
                **self.ranger_config["headers"],
                "X-Requested-By": "ranger"
            }
        )

        self._assert_response(response, 200)

        updated_data = response.json()
        self._external_user_schema_validation(updated_data)
        assert "ROLE_USER" in updated_data["vXStrings"][0]["value"]

    @pytest.mark.delete
    @pytest.mark.positive
    def test_delete_secure_user_by_id(self, request, client_roles):

        if "ROLE_SYS_ADMIN" not in client_roles:
            pytest.fail("Test requires admin privileges")

        target_user, user_id = request.getfixturevalue("temp_secure_user")(["ROLE_USER"])

        resp = requests.delete(
            f"{self.ranger_config['base_url']}/xusers/secure/users/id/{user_id}?forceDelete=true",
            auth=self.ranger_config["auth"],
            headers={
                **self.ranger_config["headers"],
                "X-Requested-By": "ranger"  # Mandatory for DELETE
            }
        )

        assert resp.status_code == 204, f"Failed to delete user: {resp.text}"


    @pytest.mark.delete
    @pytest.mark.positive
    def test_delete_secure_bulk_users(self, request, client_roles):

        if "ROLE_SYS_ADMIN" not in client_roles:
            pytest.fail("Test requires admin privileges")
            
        created_user1, user_id1 = request.getfixturevalue("temp_secure_user")()
        created_user2, user_id2 = request.getfixturevalue("temp_secure_user")()

        delete_payload = {
            "vXStrings": [
            {"value": created_user1["name"]},
            {"value": created_user2["name"]}
            ]
        }

        response = requests.delete(
            f"{self.ranger_config['base_url']}/xusers/secure/users/delete?forceDelete=true",
            json=delete_payload,
            auth=self.ranger_config["auth"],
            headers={
                **self.ranger_config["headers"],
                "X-Requested-By": "ranger"
            }
        )

        self._assert_response(response, 204)

        assert not self._user_exists(user_id1)
        assert not self._user_exists(user_id2)

    @pytest.mark.delete
    @pytest.mark.positive
    def test_get_deleted_user_by_name(self, request, client_roles):
        if "ROLE_SYS_ADMIN" not in client_roles:
            pytest.fail("Test requires admin privileges")

        target_user, _ = request.getfixturevalue("temp_secure_user")(["ROLE_USER"])
        user_name = target_user["name"]

        resp =requests.delete(
            f"{self.ranger_config['base_url']}/xusers/secure/users/{user_name}",
            auth=self.ranger_config["auth"],
            headers={**self.ranger_config["headers"], "X-Requested-By": "ranger"}
        )

        assert resp.status_code == 204, f"Failed to delete user: {resp.text}"

        response = requests.get(
            f"{self.ranger_config['base_url']}/xusers/secure/users/{user_name}",
            auth=self.ranger_config["auth"]
        )
        self._assert_response(response, 404)
       

    # NEGATIVE TESTS
    @pytest.mark.get
    @pytest.mark.negative
    @pytest.mark.parametrize("auth", [
        ("wrong_user", "wrong_pass"),
        ("admin", "wrong_pass"),
        ("", ""),
    ])
    def test_unauthorized_access(self, auth):

        response = requests.get(
            f"{self.ranger_config['base_url']}/xusers/secure/users/1",
            auth=auth
        )

        assert response.status_code in [401, 403]

    @pytest.mark.get
    @pytest.mark.negative
    def test_missing_auth(self):

        response = requests.get(
            f"{self.ranger_config['base_url']}/xusers/secure/users/1"
        )

        assert response.status_code in [401, 403]

    @pytest.mark.get
    @pytest.mark.negative
    def test_non_existing_user(self):

        response = requests.get(
            f"{self.ranger_config['base_url']}/xusers/secure/users/-990984",
            auth=self.ranger_config["auth"],
            headers=self.ranger_config["headers"]
        )

        assert response.status_code in [400, 404]

    @pytest.mark.get
    @pytest.mark.negative
    @pytest.mark.parametrize("invalid_id", [
        "abc",
        "-12345",
        "east or west ranger is the best",
    ])
    def test_invalid_input(self, invalid_id):

        response = requests.get(
            f"{self.ranger_config['base_url']}/xusers/secure/users/{invalid_id}",
            auth=self.ranger_config["auth"],
            headers=self.ranger_config["headers"]
        )

        assert response.status_code in [400, 404]
    
    @pytest.mark.get
    @pytest.mark.negative
    def test_get_user_no_permission(self, request):
        new_role_user,id= request.getfixturevalue("temp_secure_user")(["user"]) 
        response = requests.get(
            f"{self.ranger_config['base_url']}/xusers/secure/users/28", 
            auth=(new_role_user["name"], "Admin@123"), 
            headers=self.ranger_config["headers"]
        )

        assert response.status_code != 200, f"ROLE_USER should not access secure endpoint"

    @pytest.mark.get
    @pytest.mark.negative
    def test_get_keyadmin_no_permission(self):

        response = requests.get(
            f"{self.ranger_config['base_url']}/xusers/secure/users/1", 
            auth=self.ranger_key_admin_config["auth"], # note enter the true credentials of user with ROLE_KEYADMIN.
            headers=self.ranger_config["headers"]
        )
        assert response.status_code != 200, f"ROLE_KEY_ADMIN should not access secure admin's details"

    @pytest.mark.get
    @pytest.mark.negative
    @pytest.mark.parametrize("target_role", ("user",  "keyadmin"),)
    def test_get_secure_external_user_invalid_role(self, request, target_role):
        
        if target_role == "keyadmin":
            authorization = self.ranger_key_admin_config["auth"]
            target_user, target_id = request.getfixturevalue("temp_secure_user")(["admin"]) # keyadmin cann't  access admin
             
        else:
            target_user, target_id = request.getfixturevalue("temp_secure_user")(["user"])
            auth_user, auth_id = request.getfixturevalue("temp_secure_user")([target_role])
            authorization = (auth_user["name"], "Test@123")

        response = requests.get(
        f"{self.ranger_config['base_url']}/xusers/secure/users/external/{target_id}",
            auth=authorization,
            headers=self.ranger_config["headers"]
        )

        assert response.status_code == 403, f"{target_role} should not access external user endpoint, but got {response.status_code}"

    @pytest.mark.post
    @pytest.mark.negative
    def test_create_secure_user_missing_name(self):

        payload = {
        # "name" missing
        "firstName": "PyTest",
        "lastName": "User",
        "emailAddress": "missingname@test.com",
        "password": "Test@123",
        "status": 1,
        "isVisible": 1,
        "userRoleList": ["ROLE_USER"],
        "groupIdList": [],
        "groupNameList": []
        }

        response = requests.post(
        f"{self.ranger_config['base_url']}/xusers/secure/users",
        json=payload,
        auth=self.ranger_config["auth"],
        headers=self.ranger_config["headers"]
        )

        self._assert_response(response, 400)


    @pytest.mark.post
    @pytest.mark.negative
    def test_create_secure_user_duplicate_username(self):
        

        random_suffix = ''.join(random.choices(string.ascii_lowercase, k=5))
        username = f"duplicate_test_user_{random_suffix}"

        payload = {
        "name": username,
        "firstName": "PyTest",
        "lastName": "User",
        "emailAddress": f"{username}@test.com",
        "password": "Test@123",
        "status": 1,
        "isVisible": 1,
        "userRoleList": ["ROLE_USER"],
        "groupIdList": [],
        "groupNameList": []
        }

        user_id = None

        try:
            # First creation → should succeed
            first_response = requests.post(
            f"{self.ranger_config['base_url']}/xusers/secure/users",
            json=payload,
            auth=self.ranger_config["auth"],
            headers=self.ranger_config["headers"]
            )

            self._assert_response(first_response, 200)

            user_id = first_response.json().get("id")
            assert user_id is not None, "User ID not returned"

            # Second creation → should fail
            second_response = requests.post(
            f"{self.ranger_config['base_url']}/xusers/secure/users",
            json=payload,
            auth=self.ranger_config["auth"],
            headers=self.ranger_config["headers"]
            )

            self._assert_response(second_response, 400)

        finally:

            if user_id:
                query_params = {
                    "forceDelete": "true"
                    }
                delete_response = requests.delete(
                f"{self.ranger_config['base_url']}/xusers/secure/users/{user_id}",
                auth=self.ranger_config["auth"],
                headers={
                    **self.ranger_config["headers"],
                    # params = query_params,  #use only when u want to force delete generally soft delete is suggested.
                    "X-Requested-By": "ranger"
                    }
                )
                print("Cleanup status:", delete_response.status_code)

    @pytest.mark.post
    @pytest.mark.negative
    def test_create_secure_user_via_invalid_roles(self, request):

        normal_user, n_id = request.getfixturevalue("temp_secure_user")(["user"])

        auditor_user, a_id = request.getfixturevalue("temp_secure_user")(["auditor"])


        users_to_test = [
        (normal_user["name"], "Test@123"),
        (auditor_user["name"], "Test@123"),
        self.ranger_key_admin_config["auth"], 
        ]

        for username, password in users_to_test:

            random_suffix = ''.join(random.choices(string.ascii_lowercase, k=5))
            blocked_username = f"blocked_{random_suffix}"

            payload = {
            "name": blocked_username,
            "firstName": "Blocked",
            "lastName": "User",
            "emailAddress": f"{blocked_username}@test.com",
            "password": "Test@123",
            "status": 1,
            "isVisible": 1,
            "userRoleList": ["ROLE_USER"],
            "groupIdList": [],
            "groupNameList": []
            }

            response = requests.post(
            f"{self.ranger_config['base_url']}/xusers/secure/users",
            json=payload,
            auth=(username, password),
            headers=self.ranger_config["headers"]
            )

            print(f"{username} → {response.status_code}")
            assert response.status_code == 403, f"{username} should not have permission to create secure users"


    @pytest.mark.get
    @pytest.mark.negative
    @pytest.mark.parametrize("auth_role, target_role", [
        ("admin", "keyadmin"),
        ("keyadmin", "auditor"),
        ("auditor", "auditor"),
        ("auditor", "admin"),
        ("auditor", "keyadmin"),
        ("auditor", "user"),
        ("user", "user"),
        ("user", "auditor"),
        ])
    def test_get_secure_user_roles_by_username_by_invalid_role(self, request, client_roles, auth_role, target_role): 
        # admin cant access keyadmin, can access the users, auditor, admin
        # keyadmin cant access admin, can access the users, keyadmin
        # auditor if it is with same name and creds it will return this is flaw in internal repo
 
        if not any(r in client_roles for r in ["ROLE_SYS_ADMIN", "ROLE_ADMIN_AUDITOR","ROLE_KEY_ADMIN"]):
            pytest.fail("Test requires admin or auditor privileges")
        if target_role == "keyadmin":
            # cant create keyadmin user, so create an keyadmin manually
            target_user,target_id = request.getfixturevalue("temp_keyadmin_user")
            assert self._user_exists(target_id, auth=self.ranger_key_admin_config["auth"]), "Pre-requisite failed: Expected keyadmin user does not exist"
            target_name = target_user["name"]
        else:    
            target_user, target_id = request.getfixturevalue("temp_secure_user")([target_role])
            target_name = target_user["name"]

        if auth_role == "admin":
            authorization = self.ranger_config["auth"]
        elif auth_role in ["auditor","user"]:
            auth_user, auth_id = request.getfixturevalue("temp_secure_user")([auth_role])
            authorization = (auth_user["name"], "Test@123")
        elif auth_role == "keyadmin":
            authorization = self.ranger_key_admin_config["auth"]

        response = requests.get(
            f"{self.ranger_config['base_url']}/xusers/secure/users/roles/userName/{target_name}",
            
            #f"{ranger_config['base_url']}/secure/users/{user_name}",
            auth=authorization,
            headers={**self.ranger_config["headers"], "X-Requested-By": "ranger"}
        )
        print("Response text:", response.text, "Response code:", response.status_code, " for auth_role:", auth_role, " target_role:", target_role)

        if auth_role == "auditor" and target_role != "keyadmin":
            self._assert_response(response, 400) # it will show invalid input data
            
        else:
            self._assert_response(response, 403)
            

    

    @pytest.mark.put
    @pytest.mark.negative
    def test_edit_secure_user_using_invalid_id(self): 

        invalid_id = -999999
        update_payload = {
        "firstName": "ShouldFail"
        }


        update_response = requests.put(
            f"{self.ranger_config['base_url']}/xusers/secure/users/{invalid_id}",
            json=update_payload,
            auth=self.ranger_config["auth"],
            headers=self.ranger_config["headers"]
            )

        assert update_response.status_code == 404, "Expected status code 404 for non-existing user ID"

    @pytest.mark.put
    @pytest.mark.negative
    def test_edit_secure_user_using_invalid_roles(self, request):

        normal_user, n_id = request.getfixturevalue("temp_secure_user")(["user"])
        auditor_user, a_id = request.getfixturevalue("temp_secure_user")(["auditor"])

        users_to_test = [
        (normal_user["name"], "Test@123"),
        (auditor_user["name"], "Test@123"),
        ]

    
        update_payload = normal_user.copy()
        update_payload["firstName"] = "ShouldNotUpdate"

        for username, password in users_to_test:

            update_response = requests.put(
            f"{self.ranger_config['base_url']}/xusers/secure/users/{n_id}",
            json=update_payload,
            auth=(username, password),
            headers=self.ranger_config["headers"]
            )

            print("we got response", update_response.status_code, " for username, ", username)

            assert update_response.status_code == 403

    @pytest.mark.put
    @pytest.mark.negative
    def test_edit_secure_user_using_invalid_payload(self, request):

        created_user, user_id = request.getfixturevalue("temp_secure_user")(["user"])

        invalid_payload = {
                "name": created_user["name"],
                # missing required fields like firstName, lastName etc.
            }

        update_response = requests.put(
                f"{self.ranger_config['base_url']}/xusers/secure/users/{user_id}",
                json=invalid_payload,
                auth=(created_user["name"], "Test@123"),
                headers=self.ranger_config["headers"]
            )

        assert update_response.status_code == 400, "Expected status code 400 for invalid payload"

    @pytest.mark.parametrize("field", [
    "name",
    "id",
    "createDate"
     ])
    @pytest.mark.put
    @pytest.mark.negative
    def test_edit_secure_mandatory_fields(self, request, field):

        created_user, user_id = request.getfixturevalue("temp_secure_user")(["user"])

        invalid_payload = created_user.copy()

        # Apply invalid modification depending on field type
        if field == "name":
            invalid_payload[field] = "shld not update"
        elif field == "id":
            invalid_payload[field] = 1  # must be an existing ID, but not the one being updated
        else:
            invalid_payload[field] = "4566:00:00Z" 
        update_response = requests.put(
        f"{self.ranger_config['base_url']}/xusers/secure/users/{user_id}",
        json=invalid_payload,
        auth=self.ranger_config["auth"],  # must use admin to test validation
        headers=self.ranger_config["headers"]
        )

        print(field, "update response code:", update_response.status_code)

        assert update_response.status_code == 400, f"Expected status code 400 when trying to modify mandatory field: {field}"



    @pytest.mark.put
    @pytest.mark.negative
    def test_update_secure_user_active_status_with_invalid_roles(self, request):

        target_user, target_id = request.getfixturevalue("temp_secure_user")()
        normal_user, n_id = request.getfixturevalue("temp_secure_user")(["user"])
        auditor_user, a_id = request.getfixturevalue("temp_secure_user")(["auditor"])

        users_to_test = [
            (normal_user["name"], "Test@123"),
            (auditor_user["name"], "Test@123"),
            self.ranger_key_admin_config["auth"],
        ]

        print(f"\nTesting active status update with unauthorized roles")

        update_payload = {
            str(target_id): 0
        }

        for username, password in users_to_test:
            print(f"Attempting update with user: {username}")
            
            response = requests.put(
                f"{self.ranger_config['base_url']}/xusers/secure/users/activestatus",
                json=update_payload,
                auth=(username, password), # Use the specific user's credentials
                headers={
                    **self.ranger_config["headers"],
                    "X-Requested-By": "ranger"
                }
            )

            assert response.status_code == 403, f"Expected 403 for user {username}, but got {response.status_code}. Response: {response.text}"

        verify_response = requests.get(
            f"{self.ranger_config['base_url']}/xusers/secure/users/{target_id}",
            auth=self.ranger_config["auth"],
            headers=self.ranger_config["headers"]
        )
        assert verify_response.json().get("status") != 0, "Security failure: Status was actually updated despite error code!"

    @pytest.mark.put
    @pytest.mark.negative
    def test_update_secure_user_visibility_with_invalid_roles(self, request):

        target_user, target_id = request.getfixturevalue("temp_secure_user")()
        normal_user, n_id = request.getfixturevalue("temp_secure_user")(["user"])
        auditor_user, a_id = request.getfixturevalue("temp_secure_user")(["auditor"])

        users_to_test = [
            (normal_user["name"], "Test@123"),
            (auditor_user["name"], "Test@123"),
            self.ranger_key_admin_config["auth"],
        ]

        print(f"\nTesting active status update with unauthorized roles")

        update_payload = {
            str(target_id): 0
        }

        for username, password in users_to_test:
            print(f"Attempting update with user: {username}")
            
            response = requests.put(
                f"{self.ranger_config['base_url']}/xusers/secure/users/visibility",
                json=update_payload,
                auth=(username, password), # Use the specific user's credentials
                headers={
                    **self.ranger_config["headers"],
                    "X-Requested-By": "ranger"
                }
            )

            assert response.status_code == 403, f"Expected 403 for user {username}, but got {response.status_code}. Response: {response.text}"

        verify_response = requests.get(
            f"{self.ranger_config['base_url']}/xusers/secure/users/{target_id}",
            auth=self.ranger_config["auth"],
            headers=self.ranger_config["headers"]
        )
        assert verify_response.json().get("isVisible") != 0, "Security failure: Visibility was actually updated despite error code!"

    @pytest.mark.parametrize("auth_role, target_role", [
        ("admin", "keyadmin"),
        ("keyadmin", "admin"),
        ("keyadmin", "auditor"),
        ("auditor", "admin"),
        ("auditor", "user"),
        ("auditor", "keyadmin"),
        ("user", "user"),        
        ("user", "admin"),
        ("user", "auditor"),
        ("user", "keyadmin"),
        ])
    @pytest.mark.put
    @pytest.mark.negative
    def test_update_secure_role_using_id_with_invalid_roles(self, auth_role, target_role, request):


        if target_role == "keyadmin":
            target_user,target_id = request.getfixturevalue("temp_keyadmin_user")
            assert self._user_exists(target_id, auth=self.ranger_key_admin_config["auth"]), "Pre-requisite failed: Expected keyadmin user does not exist"
            
        else:
            target_user, target_id = request.getfixturevalue("temp_secure_user")([target_role])

        if auth_role == "admin":
            authorization = self.ranger_config["auth"]
        elif auth_role == "keyadmin":
            authorization = self.ranger_key_admin_config["auth"]
        else:
            auth_user, auth_id = request.getfixturevalue("temp_secure_user")(["auditor"])
            authorization = (auth_user["name"], "Test@123")
            

        print(f"\nTesting role update for id: {target_id}")

        update_payload = {
            "vXStrings": [
                {"value": "ROLE_USER"}
            ]
        }

        response = requests.put(
            f"{self.ranger_config['base_url']}/xusers/secure/users/roles/{target_id}",
            json=update_payload,
            auth=authorization,
            headers={
                **self.ranger_config["headers"],
                "X-Requested-By": "ranger"
            }
        )

        self._assert_response(response, 403)



    @pytest.mark.parametrize("auth_role, target_role", [
        ("admin", "keyadmin"),
        ("keyadmin", "admin"),
        ("keyadmin", "auditor"),
        ("auditor", "admin"),
        ("auditor", "user"),
        ("auditor", "keyadmin"),
        ("user", "user"),        
        ("user", "admin"),
        ("user", "auditor"),
        ("user", "keyadmin"),
        ])
    @pytest.mark.put
    @pytest.mark.negative
    def test_update_secure_role_using_username_with_invalid_roles(self, auth_role, target_role, request):


        if target_role == "keyadmin":
            target_user,target_id = request.getfixturevalue("temp_keyadmin_user")
            assert self._user_exists(target_id, auth=self.ranger_key_admin_config["auth"]), "Pre-requisite failed: Expected keyadmin user with ID 3 does not exist"
            
        else:
            target_user, target_id = request.getfixturevalue("temp_secure_user")([target_role])

        if auth_role == "admin":
            authorization = self.ranger_config["auth"]
        elif auth_role == "keyadmin":
            authorization = self.ranger_key_admin_config["auth"]
        else:
            auth_user, auth_id = request.getfixturevalue("temp_secure_user")(["auditor"])
            authorization = (auth_user["name"], "Test@123")
            

        print(f"\nTesting role update for user: {target_user['name']}")

        update_payload = {
            "vXStrings": [
                {"value": "ROLE_USER"}
            ]
        }

        response = requests.put(
            f"{self.ranger_config['base_url']}/xusers/secure/users/roles/userName/{target_user['name']}",
            json=update_payload,
            auth=authorization,
            headers={
                **self.ranger_config["headers"],
                "X-Requested-By": "ranger"
            }
        )

        self._assert_response(response, 403)


    @pytest.mark.delete
    @pytest.mark.negative
    def test_delete_secure_users_invalid_payload(self, client_roles):

        if "ROLE_SYS_ADMIN" not in client_roles:
            assert False, "Test requires admin privileges"

        print("\nTesting bulk delete with invalid payload")

        invalid_payload = {
        "invalid": "data"
        }

        response = requests.delete(
            f"{self.ranger_config['base_url']}/xusers/secure/users/delete",
            auth=self.ranger_config["auth"],
            headers={
            **self.ranger_config["headers"],
            "X-Requested-By": "ranger"
            },
            json=invalid_payload
        )

        self._assert_response(response, 400)
    
    @pytest.mark.delete
    @pytest.mark.negative
    def test_delete_secure_user_using_invalid_id(self, client_roles):
        
        if "ROLE_SYS_ADMIN" not in client_roles:
            assert False, "Test requires admin privileges"

        print("\nTesting delete with invalid user ID")

        invalid_user_id = -999999

        response = requests.delete(
            f"{self.ranger_config['base_url']}/xusers/secure/users/id/{invalid_user_id}",
            auth=self.ranger_config["auth"],
            headers={
                **self.ranger_config["headers"],
                "X-Requested-By": "ranger"
            }
        )

        self._assert_response(response, 404)
    
    @pytest.mark.delete
    @pytest.mark.negative
    @pytest.mark.parametrize("role",["user", "auditor", "keyadmin"])
    def test_delete_secure_user_using_invalid_role(self, request, role):

        normal_user, n_id = request.getfixturevalue("temp_secure_user")(role)
        print(f"\nTesting secure delete with role: {role}")
        print(f"User ID: {n_id}")

        response = requests.delete(
            f"{self.ranger_config['base_url']}/xusers/secure/users/{n_id}",
            auth=(normal_user["name"], "Test@123"),
            headers={
            **self.ranger_config["headers"],
            "X-Requested-By": "ranger"
            }
        )

        self._assert_response(response, [403, 405])

    @pytest.mark.delete
    @pytest.mark.negative
    def test_delete_secure_user_using_invalid_payload(self, request):
        created_user, user_id = request.getfixturevalue("temp_secure_user")(["user"])

        print("\nTesting delete with invalid payload")

        invalid_payload = {
            "invalid": "data"
        }

        response = requests.delete(
            f"{self.ranger_config['base_url']}/xusers/secure/users/delete",
            auth=(created_user["name"], "Test@123"),
            headers={
                **self.ranger_config["headers"],
                "X-Requested-By": "ranger"
            },
            json=invalid_payload
        )

        self._assert_response(response, 400)

    @pytest.mark.delete
    @pytest.mark.negative
    @pytest.mark.parametrize("fatal_payload", [
        {"vXStrings": "this_is_a_string_not_a_list"},
        {"vXStrings": [{"value": 12345}]},
        {"vXStrings": [{"value": {"unexpected": "dictionary"}}]},
        [{"vXStrings": [{"value": "user1"}]}]
        ])
    def test_delete_secure_users_malformed_items(self, ranger_config, client_roles, fatal_payload):
        if "ROLE_SYS_ADMIN" not in client_roles:
            pytest.skip("Test requires admin privileges")

        response = requests.delete(
            f"{ranger_config['base_url']}/xusers/secure/users/delete?forceDelete=true",
            json=fatal_payload,
            auth=ranger_config["auth"],
            headers={**ranger_config["headers"], "X-Requested-By": "ranger"}
        )

        self._assert_response(response, 400)

    @pytest.mark.delete
    @pytest.mark.negative
    def test_delete_secure_user_using_invalid_username(self, client_roles):
        
        if "ROLE_SYS_ADMIN" not in client_roles:
            assert False, "Test requires admin privileges"

        print("\nTesting delete with invalid username")

        invalid_username = "invalid_user7890#mkc"

        response = requests.delete(
            f"{self.ranger_config['base_url']}/xusers/secure/users/{invalid_username}",
            auth=self.ranger_config["auth"],
            headers={
                **self.ranger_config["headers"],
                "X-Requested-By": "ranger"
            }
        )

        assert response.status_code == 400, f"Expected 400 for invalid username, but got {response.status_code}. Response: {response.text}"
    
    @pytest.mark.delete
    @pytest.mark.negative
    @pytest.mark.parametrize("role",["user", "auditor", "keyadmin"])
    def test_delete_secure_user_by_username_using_invalid_role(self, ranger_config, request, role):

        normal_user, n_id = request.getfixturevalue("temp_secure_user")(role)
        print(f"\nTesting secure delete with role: {role}")
        print(f"User name: {normal_user['name']}")

        response = requests.delete(
            f"{ranger_config['base_url']}/xusers/secure/users/{normal_user['name']}",
            auth=(normal_user["name"], "Test@123"),
            headers={
            **ranger_config["headers"],
            "X-Requested-By": "ranger"
            }
        )

        self._assert_response(response, [403, 405])
