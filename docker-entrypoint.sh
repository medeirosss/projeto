#!/bin/sh
set -e

cd /app

echo "Waiting for PostgreSQL at ${POSTGRES_HOST:-db}:${POSTGRES_PORT:-5432}..."
until nc -z "${POSTGRES_HOST:-db}" "${POSTGRES_PORT:-5432}"; do
  sleep 1
done

echo "Running database migrations..."
alembic -c /app/alembic.ini upgrade head

echo "Starting Magi backend..."
exec uvicorn main:app --host 0.0.0.0 --port 8443
