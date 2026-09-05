#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# EmailThreatDetection - Development Startup Script
# Concurrently starts FastAPI backend (uvicorn) and React/Vite frontend (npm)
# ==============================================================================

# 1. Determine repository root dynamically
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${SCRIPT_DIR}"
BACKEND_DIR="${REPO_ROOT}/backend"
FRONTEND_DIR="${REPO_ROOT}/frontend"

echo "==================================================================="
echo "     Email Threat Detection & Forensics - Development Launcher    "
echo "==================================================================="

# 2. Verify directories exist
if [[ ! -d "${BACKEND_DIR}" ]]; then
    echo "[ERROR] Backend directory not found: ${BACKEND_DIR}" >&2
    exit 1
fi

if [[ ! -d "${FRONTEND_DIR}" ]]; then
    echo "[ERROR] Frontend directory not found: ${FRONTEND_DIR}" >&2
    exit 1
fi

# 3. Resolve Python interpreter (prefer local virtual environments if present)
PYTHON_BIN=""
if [[ -x "${BACKEND_DIR}/.venv/bin/python" ]]; then
    PYTHON_BIN="${BACKEND_DIR}/.venv/bin/python"
elif [[ -x "${REPO_ROOT}/.venv/bin/python" ]]; then
    PYTHON_BIN="${REPO_ROOT}/.venv/bin/python"
elif [[ -x "${BACKEND_DIR}/venv/bin/python" ]]; then
    PYTHON_BIN="${BACKEND_DIR}/venv/bin/python"
elif [[ -x "${REPO_ROOT}/venv/bin/python" ]]; then
    PYTHON_BIN="${REPO_ROOT}/venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
else
    echo "[ERROR] No Python interpreter found in PATH." >&2
    exit 1
fi

# 4. Verify backend dependencies (uvicorn & fastapi)
if ! "${PYTHON_BIN}" -c "import fastapi, uvicorn" >/dev/null 2>&1; then
    echo "[ERROR] Required backend dependencies (fastapi, uvicorn) not found in Python (${PYTHON_BIN})." >&2
    echo "[ERROR] Please install them using:" >&2
    echo "        pip install -r ${BACKEND_DIR}/requirements.txt" >&2
    exit 1
fi

# 5. Verify Node & npm availability and frontend dependencies
if ! command -v npm >/dev/null 2>&1; then
    echo "[ERROR] 'npm' command not found in PATH. Please install Node.js and npm." >&2
    exit 1
fi

if [[ ! -d "${FRONTEND_DIR}/node_modules" ]]; then
    echo "[ERROR] Frontend dependencies not found in '${FRONTEND_DIR}/node_modules'." >&2
    echo "[ERROR] Please install them using:" >&2
    echo "        (cd ${FRONTEND_DIR} && npm install)" >&2
    exit 1
fi

# 6. Resolve ports
BACKEND_PORT="8000"

# Detect Vite port from frontend/vite.config.ts if configured, fallback to 3000 or 5173
FRONTEND_PORT="3000"
if [[ -f "${FRONTEND_DIR}/vite.config.ts" ]]; then
    DETECTED_PORT=$(grep -oE 'port:\s*[0-9]+' "${FRONTEND_DIR}/vite.config.ts" | grep -oE '[0-9]+' | head -n 1 || true)
    if [[ -n "${DETECTED_PORT}" ]]; then
        FRONTEND_PORT="${DETECTED_PORT}"
    fi
elif [[ -f "${FRONTEND_DIR}/vite.config.js" ]]; then
    DETECTED_PORT=$(grep -oE 'port:\s*[0-9]+' "${FRONTEND_DIR}/vite.config.js" | grep -oE '[0-9]+' | head -n 1 || true)
    if [[ -n "${DETECTED_PORT}" ]]; then
        FRONTEND_PORT="${DETECTED_PORT}"
    fi
fi

# 7. Check port availability without terminating unrelated processes
check_port() {
    local port="$1"
    local name="$2"
    if ! "${PYTHON_BIN}" -c "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('0.0.0.0', int('$port'))); s.close()" 2>/dev/null; then
        echo "[ERROR] Port ${port} (${name}) is already in use by another process." >&2
        echo "[ERROR] Please free port ${port} or terminate the conflicting process before starting." >&2
        return 1
    fi
    return 0
}

check_port "${BACKEND_PORT}" "FastAPI Backend"
check_port "${FRONTEND_PORT}" "React/Vite Frontend"

# 8. Load environment configuration if available (do not log sensitive values)
if [[ -f "${REPO_ROOT}/.env" ]]; then
    echo "[CONFIG] Loaded environment settings from ${REPO_ROOT}/.env"
    set -a
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" =~ ^[[:space:]]*# ]] || [[ -z "${line// }" ]]; then
            continue
        fi
        export "$line" 2>/dev/null || true
    done < "${REPO_ROOT}/.env"
    set +a
elif [[ -f "${BACKEND_DIR}/.env" ]]; then
    echo "[CONFIG] Loaded environment settings from ${BACKEND_DIR}/.env"
    set -a
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" =~ ^[[:space:]]*# ]] || [[ -z "${line// }" ]]; then
            continue
        fi
        export "$line" 2>/dev/null || true
    done < "${BACKEND_DIR}/.env"
    set +a
fi

# 9. Concurrency & process management (clean signal trapping)
BACKEND_PID=""
FRONTEND_PID=""

cleanup() {
    # Prevent recursive trap invocations
    trap - SIGINT SIGTERM EXIT
    echo ""
    echo "[SHUTDOWN] Stopping all running services..."

    if [[ -n "${BACKEND_PID}" ]] && kill -0 "${BACKEND_PID}" 2>/dev/null; then
        echo "[BACKEND] Sending SIGTERM to Uvicorn (PID: ${BACKEND_PID})..."
        kill -TERM "${BACKEND_PID}" 2>/dev/null || true
        pkill -TERM -P "${BACKEND_PID}" 2>/dev/null || true
    fi

    if [[ -n "${FRONTEND_PID}" ]] && kill -0 "${FRONTEND_PID}" 2>/dev/null; then
        echo "[FRONTEND] Sending SIGTERM to Vite (PID: ${FRONTEND_PID})..."
        kill -TERM "${FRONTEND_PID}" 2>/dev/null || true
        pkill -TERM -P "${FRONTEND_PID}" 2>/dev/null || true
    fi

    # Wait up to 3 seconds for graceful shutdown
    local count=0
    while { { [[ -n "${BACKEND_PID}" ]] && kill -0 "${BACKEND_PID}" 2>/dev/null; } || \
            { [[ -n "${FRONTEND_PID}" ]] && kill -0 "${FRONTEND_PID}" 2>/dev/null; }; } && \
          [[ $count -lt 6 ]]; do
        sleep 0.5
        count=$((count + 1))
    done

    # Force kill if still lingering
    if [[ -n "${BACKEND_PID}" ]] && kill -0 "${BACKEND_PID}" 2>/dev/null; then
        kill -KILL "${BACKEND_PID}" 2>/dev/null || true
        pkill -KILL -P "${BACKEND_PID}" 2>/dev/null || true
    fi
    if [[ -n "${FRONTEND_PID}" ]] && kill -0 "${FRONTEND_PID}" 2>/dev/null; then
        kill -KILL "${FRONTEND_PID}" 2>/dev/null || true
        pkill -KILL -P "${FRONTEND_PID}" 2>/dev/null || true
    fi

    echo "[SHUTDOWN] All services stopped cleanly."
}

trap cleanup SIGINT SIGTERM EXIT

# 10. Start Backend from backend/ directory
echo "[BACKEND] Executing: ${PYTHON_BIN} -m uvicorn app.main:app --host 0.0.0.0 --port ${BACKEND_PORT}"
(
    cd "${BACKEND_DIR}"
    exec "${PYTHON_BIN}" -m uvicorn app.main:app --host 0.0.0.0 --port "${BACKEND_PORT}"
) &
BACKEND_PID=$!
echo "[BACKEND] Started successfully (PID: ${BACKEND_PID})"

# 11. Start Frontend from frontend/ directory
echo "[FRONTEND] Executing: npm run dev"
(
    cd "${FRONTEND_DIR}"
    exec npm run dev
) &
FRONTEND_PID=$!
echo "[FRONTEND] Started successfully (PID: ${FRONTEND_PID})"

echo ""
echo "==================================================================="
echo "  Email Threat Detection & Forensics Suite is running"
echo "==================================================================="
echo "  ► Backend API:     http://localhost:${BACKEND_PORT}"
echo "  ► OpenAPI Docs:    http://localhost:${BACKEND_PORT}/docs"
echo "  ► Health Check:    http://localhost:${BACKEND_PORT}/api/health"
echo "  ► React Frontend:  http://localhost:${FRONTEND_PORT}"
echo "==================================================================="
echo "Live output streaming below. Press [Ctrl+C] to stop both services."
echo ""

# Wait for either process to terminate; cleanup will terminate the other
wait -n "${BACKEND_PID}" "${FRONTEND_PID}" 2>/dev/null || true

if ! kill -0 "${BACKEND_PID}" 2>/dev/null; then
    echo "[BACKEND] Process exited."
fi
if ! kill -0 "${FRONTEND_PID}" 2>/dev/null; then
    echo "[FRONTEND] Process exited."
fi
