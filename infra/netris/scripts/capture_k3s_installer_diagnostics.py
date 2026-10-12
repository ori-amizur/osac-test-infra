#!/usr/bin/env python3
"""Capture redacted K3s Helm installer pod logs and related events."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from capture_caas_worker_diagnostics import redact_text


def run_kubectl(args: list[str], timeout: int = 45) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            ["kubectl", "--request-timeout=10s", *args], capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def append_command_output(sections: list[str], title: str, args: list[str]) -> subprocess.CompletedProcess[str] | None:
    result = run_kubectl(args)
    sections.append(f"\n=== {title} ===")
    if result is None:
        sections.append("kubectl command could not complete")
    else:
        sections.append(result.stdout.rstrip() or "(no output)")
        if result.stderr.strip():
            sections.append(f"stderr:\n{result.stderr.rstrip()}")
        if result.returncode:
            sections.append(f"kubectl exited with status {result.returncode}")
    return result


def capture(output_path: Path) -> None:
    sections: list[str] = []

    append_command_output(
        sections,
        "Warning events",
        ["get", "events", "--all-namespaces", "--field-selector=type=Warning", "--sort-by=.metadata.creationTimestamp"],
    )

    pod_result = run_kubectl(["get", "pods", "--all-namespaces", "-o", "json"])
    sections.append("\n=== Helm installer pod summary ===")
    if pod_result is None or pod_result.returncode:
        if pod_result is None:
            sections.append("kubectl could not list pods")
        else:
            sections.append(pod_result.stderr.rstrip() or f"kubectl exited with status {pod_result.returncode}")
        pods: list[dict[str, Any]] = []
    else:
        try:
            objects = json.loads(pod_result.stdout).get("items", [])
        except json.JSONDecodeError:
            objects = []
            sections.append("kubectl returned invalid pod JSON")
        pods = [pod for pod in objects if str(pod.get("metadata", {}).get("name", "")).startswith("helm-install-")]

    if not pods:
        sections.append("No helm-install-* pods found")

    for pod in pods:
        metadata = pod.get("metadata", {})
        name = str(metadata.get("name", ""))
        namespace = str(metadata.get("namespace", "default"))
        identifier = f"{namespace}/{name}"

        append_command_output(
            sections,
            f"Pod status: {identifier}",
            [
                "get",
                "pod",
                name,
                "--namespace",
                namespace,
                "-o",
                "custom-columns=NAME:.metadata.name,PHASE:.status.phase,READY:.status.containerStatuses[*].ready,RESTARTS:.status.containerStatuses[*].restartCount,NODE:.spec.nodeName",
                "--no-headers",
            ],
        )
        append_command_output(
            sections,
            f"Pod events: {identifier}",
            [
                "get",
                "events",
                "--namespace",
                namespace,
                f"--field-selector=involvedObject.name={name}",
                "--sort-by=.metadata.creationTimestamp",
            ],
        )

        status_by_name: dict[str, dict[str, Any]] = {
            str(status.get("name", "")): status for status in pod.get("status", {}).get("containerStatuses", [])
        }
        for container in pod.get("spec", {}).get("containers", []):
            container_name = str(container.get("name", ""))
            if not container_name:
                continue
            prefix = f"{identifier} container {container_name}"
            append_command_output(
                sections,
                f"Current logs: {prefix}",
                ["logs", name, "--namespace", namespace, "--container", container_name, "--timestamps", "--tail=200"],
            )
            if int(status_by_name.get(container_name, {}).get("restartCount", 0)) > 0:
                append_command_output(
                    sections,
                    f"Previous logs: {prefix}",
                    [
                        "logs",
                        name,
                        "--namespace",
                        namespace,
                        "--container",
                        container_name,
                        "--previous",
                        "--timestamps",
                        "--tail=200",
                    ],
                )

    text = "\n".join(sections).strip() + "\n"
    for secret_name in ("NETRIS_PASSWORD",):
        secret = os.environ.get(secret_name, "")
        if secret:
            text = text.replace(secret, "[REDACTED]")
    text = redact_text(text)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(text, encoding="utf-8")
    output_path.chmod(0o600)


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {Path(sys.argv[0]).name} OUTPUT_PATH", file=sys.stderr)
        return 2
    capture(Path(sys.argv[1]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
