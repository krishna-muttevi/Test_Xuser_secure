import subprocess
import requests

SERVICE_CONTAINERS = {
    "kms": "ranger-kms",
    "admin": "ranger",          # covers xuserrest, servicerest
    "usersync": "ranger-usersync",
    "tagsync": "ranger-tagsync"
}

def assert_creator_is_admin(self, ranger_config):
    username = ranger_config["auth"][0]

    response = requests.get(
        f"{ranger_config['base_url']}/service/xusers/users/userName/{username}",
        auth=ranger_config["auth"],
        headers=ranger_config["headers"]
    )

    assert response.status_code == 200, \
        f"Failed to fetch creator user details: {response.text}"

    data = response.json()

    roles = data.get("userRoleList", [])

    assert "ROLE_SYS_ADMIN" in roles, \
        f"User {username} is not admin. Roles found: {roles}"

def fetch_logs(service="admin", lines=200):
    """
    Args:
        service (str): kms | admin | usersync | tagsync
        lines (int): number of recent log lines to inspect
    Returns:
        str: Filtered error logs
    """

    container = SERVICE_CONTAINERS.get(service)

    if not container:
        return f"Unknown service: {service}"

    try:
        cmd = ["docker", "logs", "--tail", str(lines), container]
        logs = subprocess.check_output(cmd, text=True)

        error_logs = [
            line for line in logs.split("\n")
            if "ERROR" in line or "Exception" in line
        ]

        return "\n".join(error_logs) if error_logs else "No recent errors."

    except Exception as e:
        return f"Failed to fetch logs from {container}: {str(e)}"