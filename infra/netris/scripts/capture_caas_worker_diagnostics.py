#!/usr/bin/env python3
"""Capture CaaS worker serial output and a redacted provisioning snapshot."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

VM_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,252}$")
PEM_RE = re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", re.DOTALL)
BEARER_RE = re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]+")
SENSITIVE_FIELD_RE = re.compile(
    r"(?i)([\"']?[A-Za-z0-9_.-]*(?:password|passwd|token|secret|private[_-]?key|"
    r"pull[_-]?secret|credential|authorization|api[_-]?key|access[_-]?key|"
    r"template[_-]?parameters|extra[_-]?vars|user[_-]?data|proxy|ignition[_-]?config)"
    r"[A-Za-z0-9_.-]*[\"']?\s*[:=]\s*)(.*)$"
)
SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "token",
    "secret",
    "privatekey",
    "pullsecret",
    "credential",
    "authorization",
    "apikey",
    "accesskey",
    "templateparameters",
    "extravars",
    "userdata",
    "proxy",
    "ignitionconfig",
)
MAX_SERIAL_LOG_BYTES = 20 * 1024 * 1024


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()  # noqa: UP017 -- support Python 3.9 runners


def write_json(path: Path, value: Any) -> None:  # noqa: ANN401 -- values are decoded Kubernetes JSON
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o644)


def write_text(path: Path, value: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8", errors="replace")
    path.chmod(mode)


def run_command(argv: list[str], timeout: int = 45) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None


def redact_text(value: str) -> str:
    """Redact common credential formats before writing diagnostic artifacts."""
    value = PEM_RE.sub("<PRIVATE KEY REDACTED>", value)
    value = BEARER_RE.sub(r"\1<REDACTED>", value)

    redacted: list[str] = []
    block_indent: int | None = None
    for line in value.splitlines():
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        if block_indent is not None:
            if indent > block_indent or (indent == block_indent and stripped.startswith(("}", "]"))):
                redacted.append(" " * indent + "<REDACTED>")
                if indent == block_indent and stripped.startswith(("}", "]")):
                    block_indent = None
                continue
            block_indent = None

        match = SENSITIVE_FIELD_RE.search(line)
        if match:
            redacted.append(line[: match.start(2)] + "<REDACTED>")
            if match.group(2).strip() in {"", "|", "|-", "|+", ">", ">-", ">+", "{", "["}:
                block_indent = indent
            continue
        redacted.append(line)

    return "\n".join(redacted) + ("\n" if value.endswith("\n") else "")


def is_sensitive_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", key.lower())
    return any(part in normalized for part in SENSITIVE_KEY_PARTS)


def sanitize(value: Any, key: str = "") -> Any:  # noqa: ANN401 -- recursively handles decoded Kubernetes JSON
    if key and is_sensitive_key(key):
        return "<REDACTED>"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for child_key, child_value in value.items():
            if child_key in {"managedFields", "kubectl.kubernetes.io/last-applied-configuration"}:
                continue
            result[child_key] = sanitize(child_value, str(child_key))
        return result
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def process_matches(pid: int, vm_name: str) -> bool:
    try:
        command = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ")
    except OSError:
        return False
    return b"virsh" in command and b"console" in command and vm_name.encode() in command


def pid_is_running(pid: int) -> bool:
    try:
        status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
    except OSError:
        return False
    for line in status.splitlines():
        if line.startswith("State:"):
            return not line.endswith("(zombie)")
    return True


def compile_patterns(patterns: list[str]) -> tuple[list[re.Pattern[str]], list[str]]:
    compiled: list[re.Pattern[str]] = []
    errors: list[str] = []
    for pattern in patterns:
        try:
            compiled.append(re.compile(pattern))
        except re.error as exc:
            errors.append(f"Invalid VM pattern {pattern!r}: {exc}")
    return compiled, errors


def matching_names(names: list[str], patterns: list[re.Pattern[str]]) -> list[str]:
    return sorted({name for name in names if any(pattern.search(name) for pattern in patterns)})


def get_libvirt_domains() -> tuple[list[str], str | None]:
    result = run_command(["virsh", "list", "--all", "--name"])
    if result is None:
        return [], "virsh list failed or timed out"
    if result.returncode != 0:
        return [], redact_text(result.stderr.strip() or "virsh list returned a failure")
    return [line.strip() for line in result.stdout.splitlines() if line.strip()], None


def start_serial_capture(output_dir: Path, patterns: list[str]) -> None:
    console_dir = output_dir / "worker-consoles"
    console_dir.mkdir(parents=True, exist_ok=True)
    compiled, errors = compile_patterns(patterns)
    domains, domain_error = get_libvirt_domains()
    if domain_error:
        errors.append(domain_error)

    matched = matching_names(domains, compiled)
    captures: list[dict[str, str]] = []
    if not shutil.which("script") or not shutil.which("timeout"):
        errors.append("Serial capture requires util-linux script and timeout")
    else:
        for vm_name in matched:
            if not VM_NAME_RE.fullmatch(vm_name):
                captures.append({"vm": vm_name, "state": "skipped: invalid libvirt domain name"})
                continue

            pid_file = console_dir / f"worker-{vm_name}.pid"
            log_file = console_dir / f"worker-{vm_name}.serial.log"
            if pid_file.exists():
                try:
                    existing_pid = int(pid_file.read_text(encoding="utf-8").strip())
                except (OSError, ValueError):
                    existing_pid = -1
                if existing_pid > 0 and process_matches(existing_pid, vm_name):
                    captures.append({"vm": vm_name, "state": "already armed", "pid": str(existing_pid)})
                    continue
                pid_file.unlink(missing_ok=True)

            initial_state = run_command(["virsh", "domstate", vm_name])
            initially_running = (
                initial_state is not None
                and initial_state.returncode == 0
                and initial_state.stdout.strip().lower() == "running"
            )
            console_command = f"virsh console --safe {shlex.quote(vm_name)}"
            console_capture_argv = [
                "timeout",
                "--signal=INT",
                "--kill-after=10s",
                "12h",
                "script",
                "-q",
                "-f",
                "-c",
                console_command,
                "/dev/null",
            ]
            # CaaS workers are intentionally powered off until the ClusterOrder
            # provisions their BMI. Keep a watcher attached now so it opens the
            # console as soon as Metal3 powers the VM for the order InfraEnv.
            watcher_command = (
                "while true; do "
                f"state=$(virsh domstate {shlex.quote(vm_name)} 2>/dev/null "
                "| tr -d '\\r' | tr '[:upper:]' '[:lower:]' || true); "
                "if [[ \"$state\" == running ]]; then "
                f"printf 'VM {vm_name} detected running at %s; attaching serial console\\n' "
                '"$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"; '
                f"exec {shlex.join(console_capture_argv)}; "
                "fi; sleep 0.2; done"
            )
            try:
                with log_file.open("wb") as log_stream:
                    log_stream.write(
                        f"Serial console watcher started {utc_now()} for {vm_name}\n".encode()
                    )
                    log_stream.flush()
                    process = subprocess.Popen(
                        ["bash", "-c", watcher_command],
                        stdin=subprocess.DEVNULL,
                        stdout=log_stream,
                        stderr=subprocess.STDOUT,
                        start_new_session=True,
                        close_fds=True,
                    )
                pid_file.write_text(f"{process.pid}\n", encoding="ascii")
                pid_file.chmod(0o600)
                time.sleep(1)
                return_code = process.poll()
                if return_code is not None:
                    pid_file.unlink(missing_ok=True)
                    captures.append({"vm": vm_name, "state": f"console exited immediately ({return_code})"})
                else:
                    state = "attaching to running VM" if initially_running else "armed; waiting for VM power-on"
                    captures.append({"vm": vm_name, "state": state, "pid": str(process.pid)})
            except OSError as exc:
                captures.append({"vm": vm_name, "state": f"not started: {exc}"})

    write_json(
        console_dir / "capture-start.json",
        {
            "capturedAt": utc_now(),
            "patterns": patterns,
            "matchedDomains": matched,
            "captures": captures,
            "errors": errors,
        },
    )
    armed = sum("pid" in item for item in captures)
    print(f"Serial capture targets={len(matched)} armed={armed}")


def stop_serial_capture(output_dir: Path) -> list[dict[str, str]]:
    console_dir = output_dir / "worker-consoles"
    console_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, str]] = []

    for pid_file in sorted(console_dir.glob("worker-*.pid")):
        vm_name = pid_file.name.removeprefix("worker-").removesuffix(".pid")
        try:
            pid = int(pid_file.read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            pid_file.unlink(missing_ok=True)
            results.append({"vm": vm_name, "state": "removed invalid pid file"})
            continue

        if not VM_NAME_RE.fullmatch(vm_name) or not process_matches(pid, vm_name):
            pid_file.unlink(missing_ok=True)
            results.append({"vm": vm_name, "state": "capture process already stopped or changed"})
            continue

        try:
            os.killpg(pid, signal.SIGINT)
        except ProcessLookupError:
            pass
        except OSError as exc:
            results.append({"vm": vm_name, "state": f"could not signal capture: {exc}"})

        for _ in range(100):
            if not pid_is_running(pid):
                break
            time.sleep(0.1)
        if pid_is_running(pid) and process_matches(pid, vm_name):
            with suppress(OSError):
                os.killpg(pid, signal.SIGTERM)
            for _ in range(50):
                if not pid_is_running(pid):
                    break
                time.sleep(0.1)
        if pid_is_running(pid) and process_matches(pid, vm_name):
            with suppress(OSError):
                os.killpg(pid, signal.SIGKILL)

        pid_file.unlink(missing_ok=True)
        log_file = console_dir / f"worker-{vm_name}.serial.log"
        if log_file.exists():
            with log_file.open("ab") as log_stream:
                log_stream.write(f"\nSerial console capture stopped {utc_now()}\n".encode())
        results.append({"vm": vm_name, "state": "stopped"})

    write_json(console_dir / "capture-stop.json", {"capturedAt": utc_now(), "captures": results})
    return results


def trim_and_redact_serial_logs(console_dir: Path) -> None:
    for log_file in sorted(console_dir.glob("worker-*.serial.log")):
        data = log_file.read_bytes()
        prefix = ""
        if len(data) > MAX_SERIAL_LOG_BYTES:
            data = data[-MAX_SERIAL_LOG_BYTES:]
            prefix = "[Earlier serial output truncated to the last 20 MiB.]\n"
        sanitized = redact_text(data.decode("utf-8", errors="replace"))
        write_text(log_file, prefix + sanitized)


def oc_json(resource: str, namespace: str) -> tuple[dict[str, Any] | None, str | None]:
    result = run_command(["oc", "get", resource, "-n", namespace, "-o", "json"], timeout=60)
    if result is None:
        return None, f"oc get {resource} failed or timed out"
    if result.returncode != 0:
        return None, redact_text(result.stderr.strip() or f"oc get {resource} returned {result.returncode}")
    try:
        parsed = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        return None, f"oc get {resource} returned invalid JSON: {exc}"
    return parsed, None


def capture_resource(
    output_dir: Path, filename: str, resource: str, namespace: str, errors: list[str]
) -> list[dict[str, Any]]:
    data, error = oc_json(resource, namespace)
    if error:
        errors.append(f"{namespace}/{resource}: {error}")
        write_json(output_dir / filename, {"collectionError": error, "items": []})
        return []

    items = data.get("items", []) if isinstance(data, dict) else []
    write_json(output_dir / filename, sanitize(data))
    return items if isinstance(items, list) else []


def capture_assisted_resources(output_dir: Path, namespaces: list[str], errors: list[str]) -> list[str]:
    """Save Agent, InfraEnv, and event snapshots for each relevant namespace."""
    snapshot_paths: list[str] = []
    for namespace in dict.fromkeys(item for item in namespaces if item):
        safe_namespace = re.sub(r"[^A-Za-z0-9_.-]", "_", namespace)
        resources = (
            ("agents.agent-install.openshift.io", "agents"),
            ("infraenvs.agent-install.openshift.io", "infraenvs"),
            # NMStateConfig carries the per-host discovery network config (which
            # interface the data/VPC network uses, DHCP vs static, MAC match).
            # It is the key artifact for diagnosing a worker whose data NIC never
            # gets an IP and whose agent never registers.
            ("nmstateconfigs.agent-install.openshift.io", "nmstateconfigs"),
            ("events", "events"),
        )
        namespace_result = run_command(["oc", "get", "namespace", namespace, "-o", "json"], timeout=30)
        namespace_error = None
        namespace_missing = False
        if namespace_result is None:
            namespace_error = "oc get namespace failed or timed out"
        elif namespace_result.returncode != 0:
            namespace_error = redact_text(namespace_result.stderr.strip() or "oc get namespace returned a failure")
            namespace_missing = "not found" in namespace_error.lower()

        if namespace_error and not namespace_missing:
            errors.append(f"{namespace}/namespace: {namespace_error}")

        for resource_name, resource_suffix in resources:
            filename = f"assisted-resources/{safe_namespace}-{resource_suffix}.json"
            if namespace_missing:
                write_json(output_dir / filename, {"namespace": namespace, "namespaceExists": False, "items": []})
            elif namespace_error:
                write_json(
                    output_dir / filename,
                    {"namespace": namespace, "collectionError": namespace_error, "items": []},
                )
            else:
                capture_resource(output_dir, filename, resource_name, namespace, errors)
            snapshot_paths.append(filename)
    return snapshot_paths


def names_matching_patterns(items: list[dict[str, Any]], patterns: list[re.Pattern[str]]) -> set[str]:
    names = [str(item.get("metadata", {}).get("name", "")) for item in items]
    return set(matching_names(names, patterns))


def safe_bmh(item: dict[str, Any]) -> dict[str, Any]:
    metadata = item.get("metadata", {})
    spec = item.get("spec", {})
    return sanitize(
        {
            "apiVersion": item.get("apiVersion"),
            "kind": item.get("kind"),
            "metadata": {
                key: metadata[key]
                for key in ("name", "namespace", "uid", "creationTimestamp", "labels", "ownerReferences")
                if key in metadata
            },
            # The BMC address and credential references are deliberately omitted.
            "spec": {
                key: spec[key]
                for key in ("bootMACAddress", "online", "consumerRef", "bootMode", "automatedCleaningMode")
                if key in spec
            },
            "status": item.get("status", {}),
        }
    )


def unassigned_selected_bmhs(
    selected_bmhs: list[dict[str, Any]], worker_bmis: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Summarize selected BMHs that have no corresponding BMI assignment."""
    assigned_hosts = {
        str(bmi.get("bareMetalHost", ""))
        for bmi in worker_bmis
        if isinstance(bmi, dict) and bmi.get("bareMetalHost")
    }
    unassigned: list[dict[str, Any]] = []
    for bmh in selected_bmhs:
        metadata = bmh.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}
        name = str(metadata.get("name", ""))
        host_namespace = str(metadata.get("namespace", ""))
        host_reference = f"{host_namespace}/{name}" if host_namespace else name
        if not name or host_reference in assigned_hosts:
            continue
        spec = bmh.get("spec", {})
        status = bmh.get("status", {})
        if not isinstance(spec, dict):
            spec = {}
        if not isinstance(status, dict):
            status = {}
        conditions = status.get("conditions", [])
        if not isinstance(conditions, list):
            conditions = []
        provisioning = status.get("provisioning", {})
        if not isinstance(provisioning, dict):
            provisioning = {}
        unassigned.append(
            sanitize(
                {
                    "name": host_reference,
                    "creationTimestamp": metadata.get("creationTimestamp"),
                    "online": spec.get("online"),
                    "consumerRef": spec.get("consumerRef"),
                    "provisioned": next(
                        (
                            condition.get("status") == "True"
                            for condition in conditions
                            if isinstance(condition, dict) and condition.get("type") == "Provisioned"
                        ),
                        False,
                    ),
                    "provisioningState": provisioning.get("state"),
                    "conditions": conditions,
                }
            )
        )
    return unassigned


def collect_job_ids(clusterorders: list[dict[str, Any]], bmis: list[dict[str, Any]]) -> list[dict[str, Any]]:
    jobs_by_id: dict[str, dict[str, Any]] = {}

    def add_jobs(owner_kind: str, owner_name: str, status: dict[str, Any], keys: tuple[str, ...]) -> None:
        for key in keys:
            job_list = status.get(key, [])
            if not isinstance(job_list, list):
                continue
            for job in job_list:
                if not isinstance(job, dict):
                    continue
                job_id = str(job.get("jobID") or job.get("jobId") or "")
                if not job_id:
                    continue
                record = jobs_by_id.setdefault(
                    job_id,
                    {
                        "jobID": job_id,
                        "references": [],
                        "state": job.get("state"),
                        "type": job.get("type"),
                        "timestamp": job.get("timestamp"),
                    },
                )
                record["references"].append({"kind": owner_kind, "name": owner_name, "statusField": key})

    for order in clusterorders:
        name = str(order.get("metadata", {}).get("name", "unknown"))
        status = order.get("status", {})
        if isinstance(status, dict):
            add_jobs("ClusterOrder", name, status, ("provisioningJobs", "clusterStorageJobs"))

    for bmi in bmis:
        name = str(bmi.get("metadata", {}).get("name", "unknown"))
        status = bmi.get("status", {})
        if isinstance(status, dict):
            add_jobs("BareMetalInstance", name, status, ("provisioningJobs", "networkingJobs", "ipDiscoveryJobs"))

    return sorted(jobs_by_id.values(), key=lambda job: job["jobID"])


def capture_kubernetes_snapshot(
    output_dir: Path,
    namespace: str,
    agent_namespace: str,
    shared_discovery_namespace: str,
    bmh_namespace: str,
    patterns: list[str],
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    errors: list[str] = []
    compiled, pattern_errors = compile_patterns(patterns)
    errors.extend(pattern_errors)

    clusterorders = capture_resource(
        output_dir, "clusterorders.json", "clusterorders.osac.openshift.io", namespace, errors
    )
    bmis = capture_resource(
        output_dir, "baremetalinstances.json", "baremetalinstances.osac.openshift.io", namespace, errors
    )
    capture_resource(output_dir, "order-events.json", "events", namespace, errors)
    assisted_snapshot_paths = capture_assisted_resources(
        output_dir, [namespace, agent_namespace, shared_discovery_namespace], errors
    )

    bmh_items, bmh_error = oc_json("bmh", bmh_namespace)
    selected_bmh_names: set[str] = set()
    selected_bmhs: list[dict[str, Any]] = []
    if bmh_error:
        errors.append(f"{bmh_namespace}/bmh: {bmh_error}")
    else:
        all_bmhs = bmh_items.get("items", []) if isinstance(bmh_items, dict) else []
        selected_bmh_names = names_matching_patterns(all_bmhs, compiled)
        selected_bmhs = [item for item in all_bmhs if item.get("metadata", {}).get("name") in selected_bmh_names]
    write_json(output_dir / "worker-bmhs.json", {"items": [safe_bmh(item) for item in selected_bmhs]})

    worker_bmis: list[dict[str, Any]] = []
    for bmi in bmis:
        metadata = bmi.get("metadata", {})
        spec = bmi.get("spec", {})
        status = bmi.get("status", {})
        external_host_id = str(spec.get("externalHostID", ""))
        external_host_name = str(spec.get("externalHostName", ""))
        bmh_name = external_host_id.rsplit("/", 1)[-1] if external_host_id else external_host_name
        if bmh_name and not VM_NAME_RE.fullmatch(bmh_name):
            bmh_name = ""
        worker_bmis.append(
            {
                "bareMetalInstance": metadata.get("name"),
                "externalHostID": external_host_id,
                "externalHostName": external_host_name,
                "bareMetalHost": f"{bmh_namespace}/{bmh_name}" if bmh_name else "",
                "bareMetalHostCaptured": bmh_name in selected_bmh_names,
                "phase": status.get("phase") if isinstance(status, dict) else None,
                "provisioningJobIDs": [
                    str(job.get("jobID") or job.get("jobId"))
                    for job in (status.get("provisioningJobs", []) if isinstance(status, dict) else [])
                    if isinstance(job, dict) and (job.get("jobID") or job.get("jobId"))
                ],
            }
        )

    order_workers: list[dict[str, Any]] = []
    for order in clusterorders:
        order_name = order.get("metadata", {}).get("name", "unknown")
        status = order.get("status", {})
        for worker in status.get("workers", []) if isinstance(status, dict) else []:
            if not isinstance(worker, dict):
                continue
            order_workers.append(
                {
                    "clusterOrder": order_name,
                    "name": worker.get("name"),
                    "nodeSet": worker.get("nodeSet"),
                    "instanceType": worker.get("instanceType"),
                    "kind": worker.get("kind"),
                    "resourceID": worker.get("resourceID"),
                    "phase": worker.get("phase"),
                    "creationTimestamp": worker.get("creationTimestamp"),
                    "attemptCount": worker.get("attemptCount"),
                    "lastFailureReason": worker.get("lastFailureReason"),
                    "lastFailureMessage": worker.get("lastFailureMessage"),
                    "lastFailureTime": worker.get("lastFailureTime"),
                    "nextRetryTime": worker.get("nextRetryTime"),
                }
            )

    write_json(
        output_dir / "worker-map.json",
        sanitize(
            {
                "clusterOrderWorkers": order_workers,
                "bareMetalInstances": worker_bmis,
                "selectedBareMetalHosts": sorted(selected_bmh_names),
                "unassignedSelectedBareMetalHosts": unassigned_selected_bmhs(selected_bmhs, worker_bmis),
            }
        ),
    )
    write_json(output_dir / "aap-job-ids.json", sanitize({"jobs": collect_job_ids(clusterorders, bmis)}))

    # Preserve a short live libvirt/network snapshot beside the serial stream.
    domains, domain_error = get_libvirt_domains()
    if domain_error:
        errors.append(domain_error)
    worker_domains = matching_names(domains, compiled)
    for vm_name in worker_domains:
        if not VM_NAME_RE.fullmatch(vm_name):
            continue
        state_lines = [f"VM: {vm_name}", f"Captured at: {utc_now()}"]
        for description, argv in (
            ("domstate", ["virsh", "domstate", vm_name]),
            ("interfaces", ["virsh", "domiflist", vm_name]),
            ("ARP addresses", ["virsh", "domifaddr", vm_name, "--source", "arp"]),
            ("DHCP lease addresses", ["virsh", "domifaddr", vm_name, "--source", "lease"]),
        ):
            result = run_command(argv, timeout=20)
            state_lines.extend([f"\n=== {description} ==="])
            if result is None:
                state_lines.append("command failed or timed out")
            else:
                state_lines.append(result.stdout.rstrip())
                if result.stderr.strip():
                    state_lines.append(result.stderr.rstrip())
        write_text(
            output_dir / "worker-consoles" / f"worker-{vm_name}.libvirt.txt", redact_text("\n".join(state_lines))
        )

    write_json(
        output_dir / "collection-summary.json",
        {
            "capturedAt": utc_now(),
            "orderNamespace": namespace,
            "agentNamespace": agent_namespace,
            # Retain the old key for readers of earlier diagnostic artifacts.
            "discoveryNamespace": agent_namespace,
            "sharedDiscoveryNamespace": shared_discovery_namespace,
            "bmhNamespace": bmh_namespace,
            "clusterOrders": len(clusterorders),
            "bareMetalInstances": len(bmis),
            "workerBareMetalHosts": len(selected_bmhs),
            "unassignedSelectedBareMetalHosts": len(unassigned_selected_bmhs(selected_bmhs, worker_bmis)),
            "workerVMs": worker_domains,
            "errors": errors,
            "assistedResourceSnapshots": assisted_snapshot_paths,
            "aapStdoutLocation": "aap-jobs/ (captured by the focused redacting step)",
            "aapCaptureStatus": "aap-capture-status.json",
            "osacArtifactCopyStatus": "osac-artifact-copy-status.json",
        },
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("start", "collect"))
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--agent-namespace", "--discovery-namespace", dest="agent_namespace", required=True)
    parser.add_argument("--shared-discovery-namespace", default="")
    parser.add_argument("--bmh-namespace", required=True)
    parser.add_argument("--vm-patterns-json", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        patterns = json.loads(args.vm_patterns_json)
        if not isinstance(patterns, list) or not all(isinstance(item, str) for item in patterns):
            raise ValueError("VM patterns must be a JSON array of strings")
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"Invalid VM pattern input: {exc}", file=sys.stderr)
        return 2

    args.output_dir.mkdir(parents=True, exist_ok=True)
    if args.action == "start":
        start_serial_capture(args.output_dir, patterns)
        return 0

    stop_serial_capture(args.output_dir)
    console_dir = args.output_dir / "worker-consoles"
    trim_and_redact_serial_logs(console_dir)
    capture_kubernetes_snapshot(
        args.output_dir,
        args.namespace,
        args.agent_namespace,
        args.shared_discovery_namespace,
        args.bmh_namespace,
        patterns,
    )
    print(f"Worker diagnostics saved under {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
