#!/usr/bin/env bash
set -euo pipefail


# Load ENV

if [ -f .env ]; then
  set -o allexport
  source .env
  set +o allexport
else
  echo ".env file not found!"
  exit 1
fi

# Report Selection

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

# Input Validation

if [ $# -eq 0 ]; then
  echo "Usage: ./test.sh [kms|xuserrest|servicerest|*] [--clean]"
  exit 1
fi

CLEAN=false
VALID_SERVICES=("xuserrest" "servicerest" "kms")
SERVICES=()

for arg in "$@"; do
  if [ "$arg" == "--clean" ]; then
    CLEAN=true
  elif [ "$arg" == "*" ]; then
    SERVICES=("${VALID_SERVICES[@]}")
  else
    SERVICES+=("$arg")
  fi
done

# Filter invalid
FILTERED=()
for svc in "${SERVICES[@]}"; do
  if [[ " ${VALID_SERVICES[*]} " =~ " $svc " ]]; then
    FILTERED+=("$svc")
  fi
done

if [ ${#FILTERED[@]} -eq 0 ]; then
  SERVICES=("${VALID_SERVICES[@]}")
else
  SERVICES=("${FILTERED[@]}")
fi

echo "Selected services: ${SERVICES[*]}"

# Dependency Mapping

get_services() {
  case "$1" in
    xuserrest|servicerest) echo "postgres solr zk ranger" ;;
    kms) echo "postgres ranger kms" ;;
    ranger) echo "postgres solr zk ranger" ;;
    postgres) echo "postgres" ;;
    solr) echo "solr zk" ;;
    zk) echo "zk" ;;
    usersync) echo "ranger zk usersync" ;;
    tagsync) echo "ranger zk solr tagsync" ;;
    hadoop) echo "ranger zk hadoop" ;;
    hive) echo "hadoop ranger postgres hive" ;;
    hbase) echo "hadoop zk ranger hbase" ;;
    kafka) echo "zk kafka" ;;
    knox) echo "hadoop ranger knox" ;;
    kdc) echo "kdc" ;;
    *) echo "postgres ranger" ;;
  esac
}

# Recursive Resolution

resolve_all_services() {
  local input_services=("$@")
  local resolved=()
  local queue=("${input_services[@]}")

  while [ ${#queue[@]} -gt 0 ]; do
    svc="${queue[0]}"
    queue=("${queue[@]:1}")

    if [[ " ${resolved[@]-} " =~ " $svc " ]]; then
      continue
    fi

    resolved+=("$svc")

    deps=$(get_services "$svc")

    for d in $deps; do
      if [[ ! " ${resolved[@]-} " =~ " $d " ]]; then
        queue+=("$d")
      fi
    done
  done

  echo "${resolved[@]}"
}

ALL_SERVICES=$(resolve_all_services "${SERVICES[@]}")
read -ra UNIQUE_SERVICES <<< "$ALL_SERVICES"

# Filter Docker Services

DOCKER_SERVICES=()

for svc in "${UNIQUE_SERVICES[@]}"; do
  case "$svc" in
    postgres|solr|zk|ranger|kms|usersync|tagsync|hadoop|hive|hbase|kafka|knox|kdc)
      DOCKER_SERVICES+=("$svc")
      ;;
  esac
done

echo "Resolved services:"
printf " - %s\n" "${UNIQUE_SERVICES[@]}"

echo "Docker services:"
printf " - %s\n" "${DOCKER_SERVICES[@]}"

if [ ${#DOCKER_SERVICES[@]} -eq 0 ]; then
  echo "No valid docker services!"
  exit 1
fi

# Start Docker

cd "$RANGER_DOCKER_PATH"
export RANGER_DB_TYPE=postgres

RUNNING=$(docker ps --filter "name=ranger" --format "{{.Names}}")

if [ -z "$RUNNING" ]; then
  echo "Starting services..."

  if [[ " ${DOCKER_SERVICES[@]} " =~ " kms " ]]; then
    docker compose -f "$BASE_COMPOSE" -f "$COMPOSE_KMS" up -d "${DOCKER_SERVICES[@]}"
  else
    docker compose -f "$BASE_COMPOSE" up -d "${DOCKER_SERVICES[@]}"
  fi

  echo "Waiting for Ranger..."

  for i in {1..40}; do
    if curl -s "$RANGER_HOST/service/xusers/users" | grep -q "\["; then
      break
    fi
    sleep 5
  done

  echo "Ranger ready"
else
  echo "Reusing running containers"
fi


# Python Setup

cd "$PROJECT_PATH"

[ -d "$VENV_PATH" ] || python3 -m venv "$VENV_PATH"

source "$VENV_PATH/bin/activate"
export PYTHONPATH="$PROJECT_PATH"

pip install -r requirements.txt --quiet

# Test Paths

TEST_PATHS=()
for svc in "${SERVICES[@]}"; do
  TEST_PATHS+=("services/$svc")
done

# Reports

REPORT_NAME="report_$(IFS=_; echo "${SERVICES[*]}").html"
READ_REPORT="report_read_$(IFS=_; echo "${SERVICES[*]}").html"
WRITE_REPORT="report_write_$(IFS=_; echo "${SERVICES[*]}").html"

rm -f "$REPORT_NAME" "$READ_REPORT" "$WRITE_REPORT"


# Run Tests

case "$REPORT_MODE" in

  none)
    pytest -n "$PYTEST_WORKERS" -vs "${TEST_PATHS[@]}" -m "get"
    pytest -vs "${TEST_PATHS[@]}" -m "post or put or delete"
    ;;

  single)
    pytest -n "$PYTEST_WORKERS" -vs "${TEST_PATHS[@]}" \
      --html="$REPORT_NAME" --self-contained-html
    ;;

  separate)
    pytest -n "$PYTEST_WORKERS" -vs "${TEST_PATHS[@]}" -m "get" \
      --html="$READ_REPORT" --self-contained-html

    pytest -vs "${TEST_PATHS[@]}" -m "post or put or delete" \
      --html="$WRITE_REPORT" --self-contained-html
    ;;

esac

# Cleanup

if [ "$CLEAN" = true ]; then
  cd "$RANGER_DOCKER_PATH"
  docker compose down
fi

echo "Execution complete"