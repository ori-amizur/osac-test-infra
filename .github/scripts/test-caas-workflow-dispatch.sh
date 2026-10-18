#!/usr/bin/env bash
# Regression test: verify caas-agent-flow input reaches all required
# workflow steps in e2e-caas-full-install.yml.
#
# This tests the YAML structure (not runtime behaviour) to catch the
# exact gap that caused OSAC-5697: the workflow accepted the input but
# no code path consumed it.
#
# Run: bash .github/scripts/test-caas-workflow-dispatch.sh
set -euo pipefail

PASS=0
FAIL=0

assert_contains() {
    local desc="$1" file="$2" pattern="$3"
    if grep -qE "${pattern}" "${file}"; then
        echo "  PASS: ${desc}"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: ${desc} (pattern '${pattern}' not found in ${file})"
        FAIL=$((FAIL + 1))
    fi
}

assert_not_contains() {
    local desc="$1" file="$2" pattern="$3"
    if ! grep -qE "${pattern}" "${file}"; then
        echo "  PASS: ${desc}"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: ${desc} (pattern '${pattern}' unexpectedly found in ${file})"
        FAIL=$((FAIL + 1))
    fi
}

WF=".github/workflows/e2e-caas-full-install.yml"

echo "── Workflow input ──────────────────────────────────────────────"
assert_contains "caas-agent-flow input exists" "${WF}" "caas-agent-flow:"
assert_contains "cluster-namespace is documented" "${WF}" "cluster-namespace"

echo ""
echo "── Setup CaaS agents step ─────────────────────────────────────"
assert_contains "Setup step references CAAS_AGENT_FLOW" "${WF}" "CAAS_AGENT_FLOW"
assert_contains "Setup step calls setup-caas-agents.sh" "${WF}" "setup-caas-agents\\.sh"

echo ""
echo "── Worker network prerequisites ───────────────────────────────"
SETUP_BMH=".github/scripts/setup-virtual-bmh.sh"
assert_contains "Virtual BMH setup exports its gateway" "${SETUP_BMH}" "VIRTUAL_BMH_GATEWAY=.*\\$\\{GW_IP\\}"
assert_contains "Install uses gateway as worker NTP source" "${WF}" "additionalNTPSources\\[0\\]=.*VIRTUAL_BMH_GATEWAY"
assert_contains "Install selects the Route53 DNS driver" "${WF}" "DNS_CLASS.*dns\\.route53\\.dns"

echo ""
echo "── Agent watcher step ─────────────────────────────────────────"
assert_contains "Watcher step exists" "${WF}" "Start CaaS agent and virtual BMH watcher"
assert_contains "Watcher step gated on cluster-namespace" "${WF}" "caas-agent-flow.*cluster-namespace"
assert_contains "Watcher runs for virtual BMHs" "${WF}" "metal3-enabled.*true"
assert_contains "Watcher can disable agent setup" "${WF}" "CAAS_AGENT_WATCHER_SETUP_ENABLED"
assert_contains "Watcher sets CAAS_CLUSTER_ORDER_NAMESPACE" "${WF}" "CAAS_CLUSTER_ORDER_NAMESPACE"
assert_contains "Watcher invokes setup-caas-agents.sh" "${WF}" "bash .github/scripts/setup-caas-agents.sh"

WATCHER=".github/scripts/watch-caas-agent-namespaces.sh"
assert_contains "Watcher passes the ClusterOrder namespace" "${WATCHER}" "CAAS_CLUSTER_ORDER_NAMESPACE=.*\\$\\{namespace\\}"
assert_contains "Watcher repairs virtual BMH reboots" "${WATCHER}" "repair_virtual_bmh_reboot"
assert_contains "Watcher selects disk for virtual BMH reboot" "${WATCHER}" "BootSourceOverrideTarget.*Hdd"
assert_contains "Watcher has opt-in local DNS repair" "${WATCHER}" "CAAS_AGENT_WATCHER_LOCAL_DNS_ENABLED"
assert_contains "Watcher writes libvirt addn-hosts" "${WATCHER}" "\\.addnhosts"
assert_contains "Watcher cleans local DNS entries" "${WATCHER}" "remove_local_dns"

echo ""
echo "── Caller wires through input ─────────────────────────────────"
CALLER=".github/workflows/e2e-caas-full-install-caller.yml"
assert_contains "Caller has caas-agent-flow input" "${CALLER}" "caas-agent-flow:"
assert_contains "Caller passes caas-agent-flow to reusable workflow" "${CALLER}" "caas-agent-flow:.*inputs\\.caas-agent-flow"

echo ""
echo "── Teardown cleans up agent VMs ───────────────────────────────"
TEARDOWN=".github/scripts/teardown.sh"
assert_contains "Teardown cleans caas-agent VMs" "${TEARDOWN}" "caas-agent-\\\$\\{CLONE_NAME\\}"
assert_contains "Teardown removes agent disk dir" "${TEARDOWN}" "caas-agent-disks"
assert_contains "Teardown verifies CaaS agent cleanup" "${TEARDOWN}" "CAAS_LEAKED"

echo ""
echo "── No dead code: legacy no-op removed ─────────────────────────"
assert_not_contains "No reference to removed installer script" "${WF}" "INSTALLER_DIR.*setup-caas-agents"

echo ""
echo "── Completion flag race (OSAC-5697 review fix) ────────────────"
SETUP=".github/scripts/setup-caas-agents.sh"
# SETUP_COMPLETED must be set before the final info message so the
# EXIT trap never races with exit-after-echo.
COMPLETED_LINE=$(grep -n 'SETUP_COMPLETED=1' "${SETUP}" | tail -1 | cut -d: -f1)
INFO_LINE=$(grep -n 'info "setup-caas-agents complete' "${SETUP}" | tail -1 | cut -d: -f1)
if [[ -n "${COMPLETED_LINE}" && -n "${INFO_LINE}" && "${COMPLETED_LINE}" -lt "${INFO_LINE}" ]]; then
    echo "  PASS: SETUP_COMPLETED set before final info message"
    PASS=$((PASS + 1))
else
    echo "  FAIL: SETUP_COMPLETED must be set before the final info message"
    FAIL=$((FAIL + 1))
fi

echo ""
echo "── CAAS_CLUSTER_ORDER_NAME absence warning (OSAC-5697 review fix) ─"
assert_contains "Warns when CAAS_CLUSTER_ORDER_NAME is absent" "${SETUP}" \
    'WARNING.*CAAS_CLUSTER_ORDER_NAME.*not set.*deletion detection'

echo ""
echo "── No dead .items[0] jq paths (OSAC-5697 review fix) ──────────"
assert_not_contains "No .items[0] on single-object HostedCluster get" \
    "${WATCHER}" '\.items\[0\]\.status\.controlPlaneEndpoint'
assert_not_contains "No .items[0] on single-object Service get" \
    "${WATCHER}" '\.items\[0\]\.status\.loadBalancer'

echo ""
echo "── BMC credentials not in process args (OSAC-5697 review fix) ─"
assert_not_contains "No --user with BMC credentials in curl args" \
    "${WATCHER}" 'curl.*--user.*bmc_'
assert_contains "Uses --netrc-file for BMC authentication" \
    "${WATCHER}" 'netrc-file'

echo ""
echo "── Regression watcher failure detection (OSAC-5697 review fix) ─"
REGRESSION_WF=".github/workflows/e2e-full-regression.yml"
assert_contains "Regression exports watcher status file" \
    "${REGRESSION_WF}" 'VIRTUAL_BMH_WATCHER_STATUS'
assert_contains "Regression checks watcher status" \
    "${REGRESSION_WF}" 'WATCHER_RESULT.*complete'

echo ""
echo "── Summary ────────────────────────────────────────────────────"
echo "  ${PASS} passed, ${FAIL} failed"
if [[ "${FAIL}" -gt 0 ]]; then
    exit 1
fi
