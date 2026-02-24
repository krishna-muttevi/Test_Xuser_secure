# Test_Xuser_secure:

A fully automated **PyTest-based REST API test framework** for validating Ranger services (XUser, KMS, Service REST).

This framework executes end-to-end testing using a single command. It:

- Starts Ranger Docker stack
- Prepares Python virtual environment
- Installs dependencies
- Executes API test cases
- Generates HTML report
- Stops Docker containers automatically


## Quick Start
./test.sh xuserrest

That’s it.

The framework handles everything end-to-end.

##  Project Structure
```
Test_Xuser_secure/
│
├── common/                      # Shared utilities & base configuration
├── services/
│   ├── xuserrest/               # XUser REST API test cases
│   ├── kms/                     # KMS API test cases
│   └── servicrest/              # Service REST test cases
│
├── conftest.py                  # Global PyTest fixtures
├── pytest.ini                   # PyTest configuration
├── requirements.txt             # Python dependencies
├── test.sh                      # Master automation script
└── README.md
```

##  Prerequisites

```
 Ranger Docker Setup

You must have Ranger source code cloned locally with:

ranger/dev-support/ranger-docker

Example path used in script:

$HOME/cloudera_code/ranger/dev-support/ranger-docker

If your Ranger path is different, update RANGER_DOCKER_PATH inside:

test.sh

Ports Required

Make sure the following ports are free:

6080 (Ranger Admin)

9292 (KMS)

Docker internal ports
```


 Installation Steps

1️⃣ Clone Repository
```
git clone https://github.com/<your-username>/Test_Xuser_secure.git

cd Test_Xuser_secure
```
2️⃣ Make Script Executable
```
chmod +x test.sh
```
 Running Tests
 Run XUser Tests
```
./test.sh xuserrest
```
 Run KMS Tests
```
./test.sh kms
```
 Run Service REST Tests
```
./test.sh servicrest
```
 What Happens Internally?

When you run:

./test.sh xuserrest

The script performs:

Starts Ranger Docker containers

Waits for services to initialize

Creates virtual environment (if not present)

Installs dependencies from requirements.txt

Runs PyTest for selected service

Generates HTML report:

report_xuserrest.html

Stops Docker containers
<img width="3456" height="2234" alt="image" src="https://github.com/user-attachments/assets/5b01c610-01a5-47a5-ae41-3f4a26b2edc5" />


Test Report

After execution, open:

report_<service>.html

Example:

report_xuserrest.html
<img width="3456" height="2234" alt="image" src="https://github.com/user-attachments/assets/0b21135f-0ab3-416f-91b9-ed0daae69a20" />


Modular service-based test execution

Centralized fixtures via conftest.py

Schema validation for secure APIs

HTML reporting support

Docker-integrated test automation

Single-command execution

## Configuration

Main configurations are controlled via:

test.sh → Docker & execution flow

conftest.py → Base URL, headers, authentication

pytest.ini → PyTest settings

##  Extending the Framework

To add new tests:

Navigate to:

services/<service_name>/

Create new file:

test_<feature>.py

Use existing fixtures:

def test_get_users(ranger_config):
    response = requests.get(f"{ranger_config['base_url']}/users/")
    assert response.status_code == 200
 Cleanup

Docker containers are automatically stopped after execution.

If needed manually:

docker compose down
