import pytest
import requests
import json
from datetime import datetime
from common.utils import fetch_logs


BIGINT_MIN = -9223372036854775808
BIGINT_MAX =  9223372036854775807


@pytest.mark.xuserrest
@pytest.mark.secure_endpoint
class TestSecureUserEndpoint:
    SERVICE_NAME = "admin"

    def _assert_response(self, response, expected_status):
        if response.status_code != expected_status:
            logs = fetch_logs(self.SERVICE_NAME)
            pytest.fail(
                f"\nExpected: {expected_status}"
                f"\nActual: {response.status_code}"
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


    # POSITIVE TESTS

    @pytest.mark.positive
    def test_secure_user_schema_validation(self, ranger_config, all_schema_following_users):

        for user in all_schema_following_users:

            response = requests.get(
                f"http://localhost:6080/service/xusers/users/{user['id']}",
                auth=ranger_config["auth"],
                headers=ranger_config["headers"]
            )

            self._assert_response(response, 200)

            assert response.headers["Content-Type"].startswith("application/json")
            assert response.elapsed.total_seconds() < 2

            data = response.json()

            self._validate_secure_user_schema(data)

            assert data["id"] == user["id"]


    # NEGATIVE TESTS

    @pytest.mark.negative
    @pytest.mark.parametrize("auth", [
        ("wrong_user", "wrong_pass"),
        ("admin", "wrong_pass"),
        ("", ""),
    ])
    def test_unauthorized_access(self, ranger_config, auth):

        response = requests.get(
            f"http://localhost:6080/service/xusers/users/1",
            auth=auth
        )

        assert response.status_code in [401, 403]


    @pytest.mark.negative
    def test_missing_auth(self, ranger_config):

        response = requests.get(
            f"http://localhost:6080/service/xusers/users/1"
        )

        assert response.status_code in [401, 403]


    @pytest.mark.negative
    def test_non_existing_user(self, ranger_config):

        response = requests.get(
            f"http://localhost:6080/service/xusers/users/-990984",
            auth=ranger_config["auth"],
            headers=ranger_config["headers"]
        )

        assert response.status_code in [400, 404]


    @pytest.mark.negative
    @pytest.mark.parametrize("invalid_id", [
        "abc",
        "-12345",
        "east or west ranger is the best",
    ])
    def test_invalid_input(self, ranger_config, invalid_id):

        response = requests.get(
            f"http://localhost:6080/service/xusers/users/{invalid_id}",
            auth=ranger_config["auth"],
            headers=ranger_config["headers"]
        )

        assert response.status_code in [400, 404]


    @pytest.mark.negative
    def test_owner_sync_consistency(self, ranger_config, all_users):

        for user in all_users:

            response = requests.get(
                f"http://localhost:6080/service/xusers/users/{user['id']}",
                auth=ranger_config["auth"],
                headers=ranger_config["headers"]
            )

            self._assert_response(response, 200)

            data = response.json()

            if data.get("syncSource"):
                assert data.get("owner") is not None, \
                    f"Owner missing for synced user {user['id']}"