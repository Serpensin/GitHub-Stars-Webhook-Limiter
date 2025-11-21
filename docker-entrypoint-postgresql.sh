#!/bin/sh
set -e

# PostgreSQL configuration
export POSTGRES_DB="${POSTGRES_DB:-starlimiter}"
export POSTGRES_USER="${POSTGRES_USER:-starlimiter}"
export POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-change_this_password}"
export PGDATA="${PGDATA:-/var/lib/postgresql/data}"

# Global variables for process management
POSTGRES_PID=""
APP_PID=""

# Signal handler for graceful shutdown
shutdown_handler() {
    echo "Received shutdown signal, initiating graceful shutdown..."
    
    # Stop the application first (if running)
    if [ -n "$APP_PID" ] && kill -0 "$APP_PID" 2>/dev/null; then
        echo "Stopping application (PID: $APP_PID)..."
        kill -TERM "$APP_PID" 2>/dev/null || true
        
        # Wait for application to stop (max 30 seconds)
        for i in $(seq 1 30); do
            if ! kill -0 "$APP_PID" 2>/dev/null; then
                echo "Application stopped gracefully"
                break
            fi
            sleep 1
        done
        
        # Force kill if still running
        if kill -0 "$APP_PID" 2>/dev/null; then
            echo "Application did not stop gracefully, force killing..."
            kill -KILL "$APP_PID" 2>/dev/null || true
        fi
    fi
    
    # Stop PostgreSQL gracefully
    if [ -n "$POSTGRES_PID" ] && kill -0 "$POSTGRES_PID" 2>/dev/null; then
        echo "Stopping PostgreSQL server (PID: $POSTGRES_PID)..."
        # Use smart shutdown mode: wait for clients to disconnect, then shutdown
        su-exec postgres pg_ctl stop -D "$PGDATA" -m smart -w -t 30 || \
        # If smart shutdown fails, try fast mode (disconnect clients, then shutdown)
        su-exec postgres pg_ctl stop -D "$PGDATA" -m fast -w -t 10 || \
        # Last resort: immediate shutdown (abort transactions)
        su-exec postgres pg_ctl stop -D "$PGDATA" -m immediate
        
        echo "PostgreSQL server stopped"
    fi
    
    echo "Shutdown complete"
    exit 0
}

# Register signal handlers
trap shutdown_handler SIGTERM SIGINT SIGQUIT

echo "Starting PostgreSQL initialization..."

# Create directory for unix sockets (needed before PostgreSQL starts)
mkdir -p /run/postgresql
chown postgres:postgres /run/postgresql

# Initialize PostgreSQL if data directory is empty
if [ ! -s "$PGDATA/PG_VERSION" ]; then
    echo "Initializing PostgreSQL database cluster..."
    
    # Create a temporary password file with proper permissions
    PWFILE=$(mktemp)
    echo "$POSTGRES_PASSWORD" > "$PWFILE"
    chmod 644 "$PWFILE"
    chown postgres:postgres "$PWFILE"
    
    # Initialize database with password file
    su-exec postgres initdb --username="$POSTGRES_USER" --pwfile="$PWFILE"
    
    # Remove temporary password file
    rm -f "$PWFILE"
    
    # Configure PostgreSQL
    echo "host all all 0.0.0.0/0 md5" >> "$PGDATA/pg_hba.conf"
    echo "listen_addresses='*'" >> "$PGDATA/postgresql.conf"
    echo "port=5432" >> "$PGDATA/postgresql.conf"
    
    # Performance tuning for high-throughput INSERT workloads
    echo "# Performance tuning" >> "$PGDATA/postgresql.conf"
    echo "shared_buffers = 256MB" >> "$PGDATA/postgresql.conf"
    echo "effective_cache_size = 1GB" >> "$PGDATA/postgresql.conf"
    echo "maintenance_work_mem = 64MB" >> "$PGDATA/postgresql.conf"
    echo "checkpoint_completion_target = 0.9" >> "$PGDATA/postgresql.conf"
    echo "wal_buffers = 16MB" >> "$PGDATA/postgresql.conf"
    echo "default_statistics_target = 100" >> "$PGDATA/postgresql.conf"
    echo "random_page_cost = 1.1" >> "$PGDATA/postgresql.conf"
    echo "effective_io_concurrency = 200" >> "$PGDATA/postgresql.conf"
    echo "work_mem = 4MB" >> "$PGDATA/postgresql.conf"
    echo "min_wal_size = 1GB" >> "$PGDATA/postgresql.conf"
    echo "max_wal_size = 4GB" >> "$PGDATA/postgresql.conf"
    
    # For bulk operations, reduce fsync overhead
    # WARNING: Less durable but much faster for bulk inserts
    echo "synchronous_commit = off" >> "$PGDATA/postgresql.conf"
    echo "wal_writer_delay = 200ms" >> "$PGDATA/postgresql.conf"
fi

# Start PostgreSQL in background
echo "Starting PostgreSQL server..."
su-exec postgres postgres -D "$PGDATA" &
POSTGRES_PID=$!

# Wait for PostgreSQL to be ready
echo "Waiting for PostgreSQL to be ready..."
until su-exec postgres pg_isready -h localhost -p 5432 -U "$POSTGRES_USER" 2>/dev/null; do
    sleep 1
done

# Create database if it doesn't exist
echo "Creating database if not exists..."
export PGPASSWORD="$POSTGRES_PASSWORD"
# Connect to 'postgres' database (always exists) to check/create our application database
su-exec postgres psql -h localhost -p 5432 -U "$POSTGRES_USER" -d postgres -tc "SELECT 1 FROM pg_database WHERE datname = '$POSTGRES_DB'" | grep -q 1 || \
    su-exec postgres createdb -h localhost -p 5432 -U "$POSTGRES_USER" "$POSTGRES_DB"

# Export PostgreSQL connection details as individual environment variables
# This ensures the application can detect PostgreSQL and use it instead of SQLite
export POSTGRES_HOST="localhost"
export POSTGRES_PORT="5432"
# POSTGRES_DB, POSTGRES_USER, and POSTGRES_PASSWORD are already set above

echo "PostgreSQL is ready!"
echo "Database: $POSTGRES_DB"
echo "User: $POSTGRES_USER"
echo "Host: $POSTGRES_HOST"
echo "Port: $POSTGRES_PORT"
echo "Starting application as appuser..."

# Start the application in background (instead of exec)
su-exec appuser "$@" &
APP_PID=$!

echo "Application started (PID: $APP_PID)"
echo "PostgreSQL running (PID: $POSTGRES_PID)"
echo "Container ready - press Ctrl+C to stop"

# Wait for either process to exit
wait $APP_PID
APP_EXIT_CODE=$?

echo "Application exited with code $APP_EXIT_CODE"

# Trigger shutdown handler
shutdown_handler
