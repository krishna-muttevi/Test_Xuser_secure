#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# CONFIGURATION — service → compose files & required containers
# Ordered intentionally: db → base → addon (startup dependency order)
# ==============================================================================

# Load ENV
if [ -f .env ]; then
  set -o allexport
  source .env
  set +o allexport
else
  echo ".env file not found!"
  exit 1
fi

# Sanity checks
if ! command -v docker >/dev/null 2>&1; then
  echo "Docker not installed"
  exit 1
fi

if ! docker ps >/dev/null 2>&1; then
  echo "Docker daemon not running — start Docker first"
  exit 1
fi

echo ":white_check_mark: Docker is running"

# ==============================================================================
# HELPERS
# ==============================================================================

# Returns ordered compose files for a service (space-separated)
get_compose_files() {
  case "$1" in
    xuserrest|servicerest)
      echo "docker-compose.ranger-db.yml docker-compose.ranger.yml"
      ;;
    kms)
      echo "docker-compose.ranger-db.yml docker-compose.ranger.yml docker-compose.ranger-kms.yml"
      ;;
  esac
}

# Returns required containers for a service (space-separated)
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

# Returns compose SERVICE names for a test service (used by 'docker compose up')
# These match the keys under 'services:' in the compose YAMLs — NOT container names
get_compose_services() {
  case "$1" in
    xuserrest|servicerest)
      echo "postgres ranger-zk ranger-solr ranger"
      ;;
    kms)
      echo "postgres ranger ranger-kms"
      ;;
  esac
}

# Build a single "docker compose -f ... -f ..." command prefix
build_compose_cmd() {
  local cmd="docker compose"
  for f in "${COMPOSE_FILES[@]}"; do
    cmd="$cmd -f $f"
  done
  echo "$cmd"
}

# Order-preserving dedup into a named array — bash 3.2 compatible (macOS default)
# Usage: dedup_into DEST_ARRAY_NAME item1 item2 ...
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

# INPUT PARSING & DEDUPLICATION
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

# Validate all service names — abort on ANY unknown/typo so nothing runs partially
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

# RESOLVE COMPOSE FILES & CONTAINERS (order-preserving dedup)

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

echo "=============================="
echo "Services  : ${SERVICES[*]}"
echo "Compose files:"
printf "  - %s\n" "${COMPOSE_FILES[@]}"
echo "Containers:"
printf "  - %s\n" "${CONTAINERS[@]}"
echo "=============================="

cd "$RANGER_DOCKER_PATH"
export RANGER_DB_TYPE=postgres

#  Detect ZK crash (only when ZK is in scope) → full teardown
# --remove-orphans cleans stale containers from old/different compose projects

COMPOSE_CMD=$(build_compose_cmd)

if [[ " ${CONTAINERS[*]} " =~ " ranger-zk " ]]; then
  ZK_STATE=$(docker inspect -f '{{.State.Status}}' ranger-zk 2>/dev/null || echo "missing")
  if [[ "$ZK_STATE" == "exited" ]]; then
    echo "⚠️  Zookeeper crashed → full environment teardown"
    echo " $COMPOSE_CMD down -v --remove-orphans"
    eval "$COMPOSE_CMD down -v --remove-orphans"
  fi
fi

#  Pre-clean container state so compose up has a clear path
#   paused   → unpause  (compose up cannot recover paused state)
#   exited / created → docker rm  (stale containers from any prior compose project
#                                   cause "container name already in use" errors;
#                                   --remove-orphans only cleans same-project orphans)

echo "Auditing container states..."
for c in "${CONTAINERS[@]}"; do
  state=$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null || echo "missing")
  case "$state" in
    running)
      echo " $c — running"
      ;;
    paused)
      echo "  $c — paused → unpausing"
      docker unpause "$c"
      ;;
    exited|created)
      echo "  $c — stopped/stale → removing so compose can recreate"
      docker rm "$c"
      ;;
    missing)
      echo "  $c — not found → compose will create"
      ;;
  esac
done

#  Bring up only containers that are NOT already running
#   Pairs CONTAINERS[] with COMPOSE_SERVICES[] by index (built in same loop).
#   Running containers are skipped entirely — avoids "name already in use" errors
#   when containers were started by a different compose project.

SERVICES_TO_START=()
for i in "${!CONTAINERS[@]}"; do
  c="${CONTAINERS[$i]}"
  svc="${COMPOSE_SERVICES[$i]}"
  state=$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null || echo "missing")
  if [[ "$state" != "running" ]]; then
    SERVICES_TO_START+=("$svc")
  fi
done

if [ ${#SERVICES_TO_START[@]} -eq 0 ]; then
  echo "All required containers already running — skipping compose up"
else
  echo "$COMPOSE_CMD up -d --no-recreate --remove-orphans ${SERVICES_TO_START[*]}"
  eval "$COMPOSE_CMD up -d --no-recreate --remove-orphans ${SERVICES_TO_START[*]}"
fi

# Wait for required containers (dynamic — only what's in scope)

echo "⏳ Waiting for required containers to be running..."
RETRIES=30

for ((i=1; i<=RETRIES; i++)); do
  ALL_UP=true

  for c in "${CONTAINERS[@]}"; do
    cstate=$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null || echo "missing")
    if [[ "$cstate" != "running" ]]; then
      ALL_UP=false
      break
    fi
  done

  if $ALL_UP; then
    echo " All required containers are running"
    break
  fi

  echo "   Attempt $i/$RETRIES — retrying in 5s..."
  sleep 5
done

# Wait for Ranger REST API

echo ":mag: Waiting for Ranger API (http://localhost:6080)..."

for i in {1..30}; do
  if curl -s --max-time 3 http://localhost:6080 >/dev/null 2>&1; then
    echo ":white_check_mark: Ranger API is ready"
    break
  fi
  echo "  :hourglass_flowing_sand: Attempt $i/30 — retrying in 5s..."
  sleep 5
done

# PYTHON SETUP

cd "$PROJECT_PATH"

[ -d "$VENV_PATH" ] || python3 -m venv "$VENV_PATH"
source "$VENV_PATH/bin/activate"
export PYTHONPATH="$PROJECT_PATH"

pip install -r requirements.txt --quiet

# TEST PATHS  (already deduplicated SERVICES — no duplicate paths)

TEST_PATHS=()
for svc in "${SERVICES[@]}"; do
  TEST_PATHS+=("services/$svc")
done

# REPORTS

REPORT_NAME="report_$(IFS=_; echo "${SERVICES[*]}").html"
READ_REPORT="report_read_$(IFS=_; echo "${SERVICES[*]}").html"
WRITE_REPORT="report_write_$(IFS=_; echo "${SERVICES[*]}").html"

rm -f "$REPORT_NAME" "$READ_REPORT" "$WRITE_REPORT"

# ==============================================================================
# RUN TESTS
# ==============================================================================

# Wrapper so test failures (pytest exit code 1) do NOT abort the whole script.
run_pytest() { pytest "$@" || true; }

# ── SINGLE combined report ─────────────────────────────────────────────────────
# pytest-html has no append mode — the only way to produce ONE file covering
# all services is a single pytest invocation with all paths passed together.
# The xuserrest parallel-GET split is skipped in this mode (one report trumps
# parallelism when the user explicitly asked for a combined view).
if [[ "$REPORT_MODE" == "single" ]]; then
  echo "======================================"
  echo "🚀 Running: ${SERVICES[*]}"
  echo "   Combined report → $REPORT_NAME"
  echo "======================================"
  run_pytest -vs "${TEST_PATHS[@]}" \
    --html="$REPORT_NAME" --self-contained-html

else
  # ── none / separate: per-service loop with hybrid strategy for xuserrest ─────
  run_tests_for_service() {
    local service_root="$1"
    local service_name
    service_name=$(basename "$service_root")
    local service_path="$service_root/tests"

    echo "======================================"
    echo " Running tests for $service_name"
    echo "======================================"

    if [[ "$service_name" == "xuserrest" ]]; then
      # GET → parallel (pytest-xdist)  |  non-GET → sequential
      echo " xuserrest: hybrid execution (parallel GET + sequential write)"

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
      echo " $service_name → sequential pytest"
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

# ==============================================================================
# CLEANUP
# ==============================================================================

if [ "$CLEAN" = true ]; then
  cd "$RANGER_DOCKER_PATH"
  echo ":broom: Tearing down: $COMPOSE_CMD down"
  eval "$COMPOSE_CMD down"
fi

echo ":white_check_mark: Execution complete"
