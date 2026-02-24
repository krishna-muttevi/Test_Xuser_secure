#!/bin/bash
set -e

SERVICE=$1

if [ -z "$SERVICE" ]; then
  echo "Usage: ./test.sh [kms|xuserrest|servicerest]"
  exit 1
fi

RANGER_DOCKER_PATH="$HOME/cloudera_code/ranger/dev-support/ranger-docker"
PROJECT_PATH="$HOME/cloudera_code/PyTest-Ranger"
VENV_PATH="$PROJECT_PATH/venv"


echo "Starting Ranger stack for: $SERVICE"

cd "$HOME/cloudera_code/ranger/dev-support/ranger-docker" || exit 1
export RANGER_DB_TYPE=postgres

case "$SERVICE" in
  kms)
    docker compose \
      -f docker-compose.ranger.yml \
      -f docker-compose.ranger-kms.yml \
      up -d --no-build
    ;;
  xuserrest|servicerest)
    docker compose \
      -f docker-compose.ranger.yml \
      up -d --no-build
    ;;
  *)
    echo "Unknown service: $SERVICE"
    exit 1
    ;;
esac

echo " Waiting for Ranger services..."
sleep 40


echo " Preparing Python environment..."
cd "$PROJECT_PATH"

if [ -d "$VENV_PATH" ]; then
  echo " Using existing virtual environment"
else
  echo "🔨 Creating new virtual environment"
  python3 -m venv venv
fi

source "$VENV_PATH/bin/activate"
export PYTHONPATH="$PROJECT_PATH"

pip install --upgrade pip > /dev/null
pip install -r requirements.txt > /dev/null


echo "Running tests for $SERVICE..."
pytest -vs services/$SERVICE --html=report_$SERVICE.html --self-contained-html


echo "Shutting down containers..."
cd "$RANGER_DOCKER_PATH"
docker compose down

echo "Report generated: report_$SERVICE.html"
echo "Execution complete."