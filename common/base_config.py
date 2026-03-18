import os


RANGER_HOST = os.getenv("RANGER_HOST", "http://localhost")


SERVICE_CONFIG = {
    "kms": {
        "port": "9292",
        "base_path": "/kms/v1"
    },
    "xuserrest": {
        "port": "6080",
        "base_path": "/service/xusers"
    },
    "servicerest": {
        "port": "6080",
        "base_path": "/service"
    }
}


def get_base_url(service_name: str) -> str:


    config = SERVICE_CONFIG.get(service_name)

    if not config:
        raise ValueError(f"Unknown service: {service_name}")

    return f"{RANGER_HOST}:{config['port']}{config['base_path']}"


# no hardcoded somewhere all the dependency shld be defined. docker file -> dependencies, no if else -> not all containers
# if it gets handled out of box
# exptn - common utilities, code, configs,
# service specific code - > service utilities and test_caases (2 files inside the service folder)
# abhi - usersync.
# service config for userssync
# on top of chinmay's code