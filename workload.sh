#!/usr/bin/env bash
# =============================================================================
# scenarios/ai-workload/workload.sh
#
# Self-contained scaffold for the mock AI agent + MCP tool server. This is the
# SINGLE SOURCE OF TRUTH for the application itself, so setup.sh (first deploy)
# and attack.sh (the enforce-pass recycle) build the exact same pod. The whole
# application — the MCP tool server, the fake model weights, and the inference
# secret — is generated here at runtime and torn down by cleanup.sh, so the lab
# is left sanitised.
#
# Sourced, exposes:
#   deploy_workload   -- (re)create configmap + service + pod, wait until Ready
#   delete_workload   -- remove pod + service + configmap
# =============================================================================

WL_NAMESPACE="${NAMESPACE:-ai-workload}"
WL_AGENT_NAMESPACE="${AGENT_NAMESPACE:-ai-agent}"
WL_TARGET_POD="${TARGET_POD:-ai-inference}"
WL_AGENT_POD="${AGENT_POD:-agent-driver}"

# Write the MCP tool server to stdout. Pure-python, stdlib only: it provisions its
# own crown jewels (weights + secret) then serves an MCP-style JSON-RPC tool API.
# No shell, no netcat, no downloader in the server itself — so the enforce controls
# that kill those never touch the legitimate process. The dangerous actions only
# happen when a tool call is dispatched (the attack surface).
_mcp_server_py() {
  cat <<'PY'
#!/usr/bin/env python3
"""MCP tool server for the 'Guard the Model' demo.

Exposes three tools via POST /mcp/tools/call (MCP-style JSON-RPC over HTTP):
  execute   -- runs a shell command via subprocess  (attack surface: bprm_check)
  read_file -- reads a file path via `cat`          (attack surface: fd_install)
  fetch     -- POSTs a file to a URL via urllib     (attack surface: tcp_v4_connect / CNP)

The server itself only uses python stdlib — no shell, no netcat — so the enforce
controls that kill shells/cat/nc never touch the legitimate server process.
"""
import http.server
import json
import os
import shlex
import socketserver
import subprocess
import urllib.request

MODEL_PATH = "/models/model.safetensors"
SECRET_PATH = "/etc/ai/api-key"
PORT = 8080
MODEL_MB = int(os.environ.get("MODEL_MB", "6"))

MCP_TOOLS = [
    {"name": "execute",   "description": "Execute a shell command on the host"},
    {"name": "read_file", "description": "Read a file from the filesystem"},
    {"name": "fetch",     "description": "Fetch a URL (optionally POST a file body)"},
]


def provision():
    os.makedirs("/models", exist_ok=True)
    os.makedirs("/etc/ai", exist_ok=True)
    if not os.path.exists(MODEL_PATH):
        with open(MODEL_PATH, "wb") as fh:
            fh.write(os.urandom(MODEL_MB * 1024 * 1024))
    if not os.path.exists(SECRET_PATH):
        with open(SECRET_PATH, "w") as fh:
            fh.write("AI_API_KEY=DEMO-NOT-A-REAL-KEY-4421-do-not-share\n")
    os.chmod(SECRET_PATH, 0o600)


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/health", "/healthz"):
            self._send(200, {"status": "ok"})
        elif self.path in ("/", "/version"):
            size = os.path.getsize(MODEL_PATH) if os.path.exists(MODEL_PATH) else 0
            self._send(200, {
                "service": "mcp-tool-server",
                "model": "demo-llm-7b",
                "weights_bytes": size,
                "status": "serving",
                "tools": [t["name"] for t in MCP_TOOLS],
            })
        elif self.path == "/mcp/tools/list":
            self._send(200, {"tools": MCP_TOOLS})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/mcp/tools/call":
            self._send(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            req = json.loads(body)
        except Exception:
            self._send(400, {"error": "invalid JSON"})
            return
        self._send(200, self._dispatch(req))

    def _dispatch(self, req):
        name = req.get("name", "")
        args = req.get("arguments", {})
        if name == "execute":
            return self._tool_execute(args)
        if name == "read_file":
            return self._tool_read_file(args)
        if name == "fetch":
            return self._tool_fetch(args)
        return {"exit_code": 1, "error": f"unknown tool: {name}"}

    def _tool_execute(self, args):
        # Runs via subprocess — security_bprm_check fires on the spawned binary.
        command = args.get("command", "")
        try:
            r = subprocess.run(shlex.split(command), capture_output=True, timeout=5)
            return {
                "exit_code": r.returncode,
                "stdout": r.stdout.decode(errors="replace"),
                "stderr": r.stderr.decode(errors="replace"),
            }
        except Exception as e:
            return {"exit_code": 1, "error": str(e)}

    def _tool_read_file(self, args):
        # Uses `cat` subprocess — fd_install fires on cat, not on python.
        path = args.get("path", "")
        try:
            r = subprocess.run(["cat", path], capture_output=True, timeout=5)
            return {
                "exit_code": r.returncode,
                "stdout": r.stdout.decode(errors="replace"),
                "stderr": r.stderr.decode(errors="replace"),
            }
        except Exception as e:
            return {"exit_code": 1, "error": str(e)}

    def _tool_fetch(self, args):
        # Uses python urllib directly (no subprocess) — python is excluded from the
        # tcp_v4_connect kill-list so CiliumNetworkPolicy, not a SIGKILL, blocks this.
        url = args.get("url", "")
        body_path = args.get("body_path", "")
        try:
            data = open(body_path, "rb").read(65536) if body_path else None
            request = urllib.request.Request(
                url, data=data, method="POST" if data else "GET"
            )
            urllib.request.urlopen(request, timeout=5)
            return {"exit_code": 0, "stdout": f"sent {len(data or b'')} bytes to {url}"}
        except Exception as e:
            return {"exit_code": 1, "error": str(e)}

    def log_message(self, *_args):  # keep the pod logs quiet
        return


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    provision()
    print(f"[mcp-tool-server] provisioned model + secret; serving on :{PORT}", flush=True)
    Server(("0.0.0.0", PORT), Handler).serve_forever()
PY
}

_ensure_namespace() {
  kubectl create namespace "$1" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
}

deploy_workload() {
  _ensure_namespace "${WL_NAMESPACE}"
  _ensure_namespace "${WL_AGENT_NAMESPACE}"

  local tmp
  tmp="$(mktemp)"
  _mcp_server_py > "${tmp}"
  kubectl -n "${WL_NAMESPACE}" delete configmap ai-inference-app --ignore-not-found >/dev/null 2>&1 || true
  kubectl -n "${WL_NAMESPACE}" create configmap ai-inference-app --from-file=agent.py="${tmp}"
  rm -f "${tmp}"

  kubectl apply -f - <<YAML
apiVersion: v1
kind: Service
metadata:
  name: ai-inference
  namespace: ${WL_NAMESPACE}
  labels:
    app: ai-inference
    lab: oss-demo
spec:
  selector:
    app: ai-inference
  ports:
    - name: http
      port: 8080
      targetPort: 8080
---
apiVersion: v1
kind: Pod
metadata:
  name: ${WL_TARGET_POD}
  namespace: ${WL_NAMESPACE}
  labels:
    app: ai-inference
    app.kubernetes.io/name: ai-inference
    lab: oss-demo
spec:
  containers:
    - name: ai-inference
      image: python:3.11-alpine
      command: ["python3", "/app/agent.py"]
      ports:
        - containerPort: 8080
      securityContext:
        runAsUser: 0
      volumeMounts:
        - name: app
          mountPath: /app
      readinessProbe:
        httpGet:
          path: /health
          port: 8080
        initialDelaySeconds: 2
        periodSeconds: 5
      resources:
        requests:
          memory: "64Mi"
          cpu: "50m"
        limits:
          memory: "192Mi"
          cpu: "200m"
  volumes:
    - name: app
      configMap:
        name: ai-inference-app
  restartPolicy: Always
  nodeSelector:
    workload: attacker
YAML

  kubectl -n "${WL_NAMESPACE}" wait --for=condition=Ready "pod/${WL_TARGET_POD}" --timeout=120s

  # -- Agent driver: SEPARATE pod in a SEPARATE namespace ----------------------
  # Every MCP tool call in attack.sh now crosses the real pod network from
  # ai-agent/agent-driver to ai-workload/ai-inference -- not kubectl-exec
  # loopback. This makes every tool call visible to Hubble and goverable by
  # the ingress-allow CiliumNetworkPolicy in network-policy.yaml.
  kubectl apply -f - <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: ${WL_AGENT_POD}
  namespace: ${WL_AGENT_NAMESPACE}
  labels:
    app: agent-driver
    app.kubernetes.io/name: agent-driver
    lab: oss-demo
spec:
  containers:
    - name: agent-driver
      image: python:3.11-alpine
      command: ["sleep", "infinity"]
      resources:
        requests:
          memory: "32Mi"
          cpu: "25m"
        limits:
          memory: "64Mi"
          cpu: "100m"
  restartPolicy: Always
YAML
  kubectl -n "${WL_AGENT_NAMESPACE}" wait --for=condition=Ready "pod/${WL_AGENT_POD}" --timeout=60s
}

delete_workload() {
  kubectl -n "${WL_NAMESPACE}" delete pod "${WL_TARGET_POD}" --ignore-not-found
  kubectl -n "${WL_NAMESPACE}" delete service ai-inference --ignore-not-found
  kubectl -n "${WL_NAMESPACE}" delete configmap ai-inference-app --ignore-not-found
  kubectl -n "${WL_AGENT_NAMESPACE}" delete pod "${WL_AGENT_POD}" --ignore-not-found
}
