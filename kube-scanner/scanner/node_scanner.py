import json
import subprocess
import time
from typing import Dict, Any, Optional, Tuple, List


_CACHE: Dict[Tuple[str, str], Tuple[float, Dict[str, Any]]] = {}


def _kubectl(args: List[str], kubeconfig: str = "") -> subprocess.CompletedProcess:
    cmd = ["kubectl"] + args
    if kubeconfig:
        cmd += ["--kubeconfig", kubeconfig]
    return subprocess.run(cmd, capture_output=True, text=True)


def _parse_kv_tokens(tokens: List[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for t in tokens:
        if "=" not in t:
            continue
        k, v = t.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def parse_node_scanner_log(log_text: str) -> Dict[str, Any]:
    """
    Parse node-scanner DaemonSet logs.

    Expected lines:
      NODE_SCANNER_NODE name=<node>
      NODE_SCANNER_FILE path=<abs> mode=<644> owner=<root> group=<root>
      NODE_SCANNER_MISSING path=<abs>
      NODE_SCANNER_SYSCTL key=<k> value=<v>
      NODE_SCANNER_KUBELET present=true has_clientCAFile=true authorization_mode=Webhook ...
    """
    data: Dict[str, Any] = {
        "node": None,
        "files": {},      # path -> {mode:int|None, owner, group, missing:bool}
        "sysctls": {},    # key -> value(str)
        "kubelet": {},    # parsed summary
    }

    for raw in log_text.splitlines():
        line = raw.strip()
        if not line:
            continue

        if line.startswith("NODE_SCANNER_NODE "):
            kv = _parse_kv_tokens(line.split()[1:])
            data["node"] = kv.get("name") or data["node"]
            continue

        if line.startswith("NODE_SCANNER_FILE "):
            kv = _parse_kv_tokens(line.split()[1:])
            path = kv.get("path")
            if not path:
                continue
            mode_val: Optional[int] = None
            if "mode" in kv and kv["mode"].isdigit():
                mode_val = int(kv["mode"], 10)
            data["files"][path] = {
                "missing": False,
                "mode": mode_val,
                "perms": kv.get("perms"),
                "owner": kv.get("owner"),
                "group": kv.get("group"),
            }
            continue

        if line.startswith("NODE_SCANNER_MISSING "):
            kv = _parse_kv_tokens(line.split()[1:])
            path = kv.get("path")
            if not path:
                continue
            data["files"][path] = {"missing": True, "mode": None, "owner": None, "group": None}
            continue

        if line.startswith("NODE_SCANNER_SYSCTL "):
            kv = _parse_kv_tokens(line.split()[1:])
            key = kv.get("key")
            if not key:
                continue
            data["sysctls"][key] = kv.get("value", "")
            continue

        if line.startswith("NODE_SCANNER_KUBELET "):
            kv = _parse_kv_tokens(line.split()[1:])
            data["kubelet"] = kv
            continue

    return data


def collect_node_scanner_data(kubeconfig: str = "", cache_ttl_sec: int = 30) -> Dict[str, Any]:
    """
    Collect node-scanner data once and cache for short TTL.

    Returns:
      {
        "available": bool,
        "error": str|None,
        "nodes": { nodeName: { "pod": str, "files":..., "sysctls":..., "kubelet":... } }
      }
    """
    cache_key = (kubeconfig or "", "node_scanner_v1")
    now = time.time()
    if cache_key in _CACHE:
        ts, val = _CACHE[cache_key]
        if now - ts <= cache_ttl_sec:
            return val

    # 1) Find node-scanner pods
    res = _kubectl(["get", "pods", "-n", "kube-system", "-l", "app=node-scanner", "-o", "json"], kubeconfig)
    if res.returncode != 0:
        out = {"available": False, "error": (res.stderr or res.stdout).strip(), "nodes": {}}
        _CACHE[cache_key] = (now, out)
        return out

    try:
        pods = json.loads(res.stdout)
    except Exception as e:
        out = {"available": False, "error": f"pod 목록 JSON 파싱 실패: {e}", "nodes": {}}
        _CACHE[cache_key] = (now, out)
        return out

    items = pods.get("items", []) or []
    if not items:
        out = {"available": False, "error": "node-scanner DaemonSet Pod가 없음 (먼저 kubectl apply -f k8s/node-scanner-daemonset.yaml 실행)", "nodes": {}}
        _CACHE[cache_key] = (now, out)
        return out

    nodes: Dict[str, Any] = {}
    for it in items:
        pod_name = it.get("metadata", {}).get("name")
        node_name = it.get("spec", {}).get("nodeName")
        if not pod_name or not node_name:
            continue

        log_res = _kubectl(["logs", "-n", "kube-system", pod_name, "--tail=3000"], kubeconfig)
        if log_res.returncode != 0:
            nodes[node_name] = {
                "pod": pod_name,
                "error": (log_res.stderr or log_res.stdout).strip(),
                "files": {},
                "sysctls": {},
                "kubelet": {},
            }
            continue

        parsed = parse_node_scanner_log(log_res.stdout or "")
        nodes[node_name] = {
            "pod": pod_name,
            "files": parsed.get("files", {}),
            "sysctls": parsed.get("sysctls", {}),
            "kubelet": parsed.get("kubelet", {}),
        }

    out = {"available": True, "error": None, "nodes": nodes}
    _CACHE[cache_key] = (now, out)
    return out

