#!/usr/bin/env bash
set -euo pipefail


# Load ENV — must run from PyTest-Ranger project root
if [ -f .env ]; then
  set -o allexport
  source .env
  set +o allexport
else
  echo ".env file not found! Run this script from the PyTest-Ranger project root."
  exit 1
fi

# RANGER_DB_TYPE must be set before ANY docker compose call — compose parses
# YAMLs immediately and fails with "service not found" if this is missing
export RANGER_DB_TYPE="${RANGER_DB_TYPE:-postgres}"

# All docker compose calls must run from RANGER_DOCKER_PATH
cd "$RANGER_DOCKER_PATH"

# Sanity checks
if ! command -v docker >/dev/null 2>&1; then
  echo "Docker not installed"
  exit 1
fi

if ! docker ps >/dev/null 2>&1; then
  echo "Docker daemon not running — start Docker first"
  exit 1
fi

echo " --- Docker is running ---"


# Returns ordered compose files for a service (space-separated)
get_compose_files() {
  case "$1" in
    xuserrest|servicerest)
      echo "docker-compose.ranger.yml"
      ;;
    kms)
      echo "docker-compose.ranger.yml docker-compose.ranger-kms.yml"
      ;;
  esac
}

# Returns required container names for a service (these are container_name: values in compose YAMLs)
get_required_containers() {
  case "$1" in
    xuserrest|servicerest)
      echo "ranger-postgres ranger-zk ranger-solr ranger"
      ;;
    kms)
      echo "ranger-postgres ranger ranger-kms"
      ;;
  esac
}

# Returns compose SERVICE keys for a service (keys under 'services:' in the YAMLs)
get_compose_services() {
  case "$1" in
    xuserrest|servicerest)
      echo "ranger-db ranger-zk ranger-solr ranger"
      ;;
    kms)
      echo "ranger-db ranger ranger-kms"
      ;;
  esac
}

# Build "docker compose -f ... -f ..." prefix from COMPOSE_FILES array
build_compose_cmd() {
  local cmd="docker compose"
  for f in "${COMPOSE_FILES[@]}"; do
    cmd="$cmd -f $f"
  done
  echo "$cmd"
}

# Order-preserving dedup into a named array — bash 3.2 compatible (macOS default)
dedup_into() {
  local _dest_name="$1"; shift
  local _result=()
  local _item _existing _found
  for _item in "$@"; do
    _found=false
    for _existing in "${_result[@]+"${_result[@]}"}"; do
      [[ "$_existing" == "$_item" ]] && _found=true && break
    done
    [[ "$_found" == false ]] && _result+=("$_item")
  done
  eval "${_dest_name}=()"
  for _item in "${_result[@]+"${_result[@]}"}"; do
    eval "${_dest_name}+=(\"\$_item\")"
  done
}

# REPORT SELECTION

echo "Do you want to generate HTML reports? (y/n)"
read -r GENERATE_REPORT

REPORT_MODE="none"

if [[ "$GENERATE_REPORT" =~ ^[Yy]$ ]]; then
  echo "Choose report type:"
  echo "1 → Single combined report"
  echo "2 → Separate reports (GET + WRITE)"
  read -r REPORT_CHOICE
  case "$REPORT_CHOICE" in
    1) REPORT_MODE="single" ;;
    2) REPORT_MODE="separate" ;;
    *) REPORT_MODE="none" ;;
  esac
fi

# INPUT PARSING & VALIDATION

if [ $# -eq 0 ]; then
  echo "Usage: ./test.sh [kms|xuserrest|servicerest|*] [--clean]"
  exit 1
fi

CLEAN=false
VALID_SERVICES=("xuserrest" "servicerest" "kms")
RAW_SERVICES=()

for arg in "$@"; do
  if [ "$arg" == "--clean" ]; then
    CLEAN=true
  elif [ "$arg" == "*" ]; then
    RAW_SERVICES+=("${VALID_SERVICES[@]}")
  else
    RAW_SERVICES+=("$arg")
  fi
done

# Validate — abort on ANY unknown service so nothing runs partially

VALID_RAW=()
for svc in "${RAW_SERVICES[@]}"; do
  if [[ " ${VALID_SERVICES[*]} " =~ " $svc " ]]; then
    VALID_RAW+=("$svc")
  else
    echo "⚠️  Unknown service: '$svc'"
    echo "   Valid options : ${VALID_SERVICES[*]}"
    echo "   Usage         : ./test.sh [kms|xuserrest|servicerest|*] [--clean]"
    exit 1
  fi
done

if [[ ${#VALID_RAW[@]} -eq 0 ]]; then
  echo "No services specified. Usage: ./test.sh [kms|xuserrest|servicerest|*] [--clean]"
  exit 1
fi

# Order-preserving dedup — e.g. "xuserrest kms xuserrest" → "xuserrest kms"
dedup_into SERVICES "${VALID_RAW[@]}"

# RESOLVE COMPOSE FILES, CONTAINERS, SERVICE KEYS

ALL_COMPOSE=()
ALL_CONTAINERS=()
ALL_COMPOSE_SVCS=()

for svc in "${SERVICES[@]}"; do
  read -ra cf  <<< "$(get_compose_files      "$svc")"
  read -ra con <<< "$(get_required_containers "$svc")"
  read -ra csv <<< "$(get_compose_services    "$svc")"
  ALL_COMPOSE+=("${cf[@]}")
  ALL_CONTAINERS+=("${con[@]}")
  ALL_COMPOSE_SVCS+=("${csv[@]}")
done

dedup_into COMPOSE_FILES    "${ALL_COMPOSE[@]}"
dedup_into CONTAINERS       "${ALL_CONTAINERS[@]}"
dedup_into COMPOSE_SERVICES "${ALL_COMPOSE_SVCS[@]}"

COMPOSE_CMD=$(build_compose_cmd)

echo "=============================="
echo "Services      : ${SERVICES[*]}"
echo "DB type       : $RANGER_DB_TYPE"
echo "Compose files :"
printf "  - %s\n" "${COMPOSE_FILES[@]}"
echo "Containers    :"
printf "  - %s\n" "${CONTAINERS[@]}"
echo "=============================="

# ENVIRONMENT SETUP — clean, audit, then bring up


# If ZK exited unexpectedly the whole stack is likely corrupt; nuke and restart.
if [[ " ${CONTAINERS[*]} " =~ " ranger-zk " ]]; then
  ZK_STATE=$(docker inspect -f '{{.State.Status}}' ranger-zk 2>/dev/null | tr -d '[:space:]' || echo "missing")
  if [[ "$ZK_STATE" == "exited" ]]; then
    echo "⚠️  ZooKeeper crashed → full environment teardown"
    $COMPOSE_CMD down -v --remove-orphans
    echo "--- Teardown complete ---"
  fi
fi

# Force-clear any container holding a name we need
# --remove-orphans only cleans containers within the same compose project.
# Containers from other projects (or docker run) holding the same name must be
# removed explicitly — otherwise compose up fails with "name already in use".
echo "Auditing container states..."
for c in "${CONTAINERS[@]}"; do
  raw=$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null || echo "missing")
  state=$(echo "$raw" | tr -d '[:space:]')   # strip all whitespace/newlines
  case "$state" in
    running)
      echo "  $c — running ✓ (keeping)"
      ;;
    paused)
      echo "  $c — paused → unpausing"
      docker unpause "$c"
      ;;
    exited|created|dead)
      echo "  $c — stopped/stale → removing"
      docker rm -f "$c"
      ;;
    missing)
      echo "  $c — not found → will be created"
      ;;
    *)
      echo "  $c — unexpected state '$state' → force removing"
      docker rm -f "$c" 2>/dev/null || true
      ;;
  esac
done

# Safety net — force-remove by name before compose up
# Docker Desktop on macOS sometimes holds name reservations in its internal
# registry even after 'down' completes. An explicit rm -f drains that cache.
echo "Clearing any residual name reservations..."
for c in "${CONTAINERS[@]}"; do
  state=$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null | tr -d '[:space:]' || echo "missing")
  if [[ "$state" != "running" && "$state" != "missing" ]]; then
    docker rm -f "$c" 2>/dev/null || true
  fi
done

# Bring up only containers that aren't already running
SERVICES_TO_START=()
for i in "${!CONTAINERS[@]}"; do
  c="${CONTAINERS[$i]}"
  svc="${COMPOSE_SERVICES[$i]}"
  state=$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null | tr -d '[:space:]' || echo "missing")
  if [[ "$state" != "running" ]]; then
    SERVICES_TO_START+=("$svc")
  fi
done

if [ ${#SERVICES_TO_START[@]} -eq 0 ]; then
  echo "--- All required containers already running — skipping compose up ---"
else
  echo "Starting: ${SERVICES_TO_START[*]}"
  $COMPOSE_CMD up -d --no-recreate --remove-orphans "${SERVICES_TO_START[@]}"
fi

echo "Waiting 60s for containers to initialise..."
sleep 60

# Restart ZK so it picks up the KDC keytab 
if [[ " ${CONTAINERS[*]} " =~ " ranger-zk " ]]; then
  echo "Restarting ZooKeeper to pick up KDC keytab..."
  docker restart ranger-zk
  sleep 20
fi

echo "Waiting for all required containers to be running..."
RETRIES=30
for ((i=1; i<=RETRIES; i++)); do
  ALL_UP=true
  for c in "${CONTAINERS[@]}"; do
    cstate=$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null | tr -d '[:space:]' || echo "missing")
    if [[ "$cstate" != "running" ]]; then
      ALL_UP=false
      break
    fi
  done
  if $ALL_UP; then
    echo "--- All required containers are running ---"
    break
  fi
  if (( i == RETRIES )); then
    echo "❌ Timed out waiting for containers. Current states:"
    for c in "${CONTAINERS[@]}"; do
      docker inspect -f "  $c — {{.State.Status}}" "$c" 2>/dev/null || echo "  $c — missing"
    done
    exit 1
  fi
  echo "   Attempt $i/$RETRIES — retrying in 5s..."
  sleep 5
done


echo "Waiting for Ranger API (http://localhost:6080)..."
for i in {1..30}; do
  if curl -s --max-time 3 http://localhost:6080 >/dev/null 2>&1; then
    echo "--- Ranger API is ready ---"
    break
  fi
  if (( i == 30 )); then
    echo "❌ Ranger API did not become ready in time"
    exit 1
  fi
  echo "   Attempt $i/30 — retrying in 5s..."
  sleep 5
done

# PYTHON SETUP

cd "$PROJECT_PATH"

[ -d "$VENV_PATH" ] || python3 -m venv "$VENV_PATH"
source "$VENV_PATH/bin/activate"
export PYTHONPATH="$PROJECT_PATH"

pip install -r requirements.txt --quiet

# TEST PATHS

TEST_PATHS=()
for svc in "${SERVICES[@]}"; do
  TEST_PATHS+=("services/$svc")
done

# REPORTS — clean up stale files before run

REPORT_NAME="report_$(IFS=_; echo "${SERVICES[*]}").html"
READ_REPORT="report_read_$(IFS=_; echo "${SERVICES[*]}").html"
WRITE_REPORT="report_write_$(IFS=_; echo "${SERVICES[*]}").html"

rm -f "$REPORT_NAME" "$READ_REPORT" "$WRITE_REPORT"

# Wrapper so test failures don't abort the whole script
run_pytest() { pytest "$@" || true; }

# RUN TESTS

if [[ "$REPORT_MODE" == "single" ]]; then
  echo "======================================"
  echo "   Running: ${SERVICES[*]}"
  echo "   Combined report → $REPORT_NAME"
  echo "======================================"
  run_pytest -vs "${TEST_PATHS[@]}" \
    --html="$REPORT_NAME" --self-contained-html

else
  # Per-service loop 
  run_tests_for_service() {
    local service_root="$1"
    local service_name
    service_name=$(basename "$service_root")
    local service_path="$service_root/tests"

    echo "======================================"
    echo " Running tests for: $service_name"
    echo "======================================"

    if [[ "$service_name" == "xuserrest" ]]; then
      echo "  xuserrest: hybrid (parallel GET + sequential write)"
      HAS_GET=$(pytest --collect-only -q "$service_path" 2>/dev/null \
                  | grep -i "\bget\b" || true)

      case "$REPORT_MODE" in
        none)
          if [ -n "$HAS_GET" ]; then
            run_pytest -n "${PYTEST_WORKERS:-4}" -vs "$service_path" -m "get"
            run_pytest -vs "$service_path" -m "not get"
          else
            run_pytest -vs "$service_path"
          fi
          ;;
        separate)
          if [ -n "$HAS_GET" ]; then
            run_pytest -n "${PYTEST_WORKERS:-4}" -vs "$service_path" -m "get" \
              --html="report_read_${service_name}.html" --self-contained-html
            run_pytest -vs "$service_path" -m "not get" \
              --html="report_write_${service_name}.html" --self-contained-html
          else
            run_pytest -vs "$service_path" \
              --html="report_${service_name}.html" --self-contained-html
          fi
          ;;
      esac

    else
      echo "  $service_name → sequential"
      case "$REPORT_MODE" in
        none)
          run_pytest -vs "$service_path"
          ;;
        separate)
          run_pytest -vs "$service_path" \
            --html="report_${service_name}.html" --self-contained-html
          ;;
      esac
    fi
  }

  for svc_path in "${TEST_PATHS[@]}"; do
    run_tests_for_service "$svc_path"
  done
fi

# CLEANUP

if [ "$CLEAN" = true ]; then
  cd "$RANGER_DOCKER_PATH"
  echo " Tearing down: $COMPOSE_CMD down"
  $COMPOSE_CMD down
fi

echo " Execution complete"
