#!/usr/bin/env bash
#
# Boot CaaS agent VMs on the cluster-tool network and register them
# with the Assisted Service running on the hub cluster.
#
# This is the cluster-tool counterpart of
# infra/agentless-net/scripts/setup-caas.sh — same agent registration
# flow (create an InfraEnv → boot VMs from discovery ISO → wait for
# agents → label/approve), adapted to run on the
# cluster-tool libvirt network instead of containerlab bridges.
#
# The VM creation pattern follows .github/scripts/setup-virtual-bmh.sh,
# which already proves this approach works on cluster-tool networks.
#
# Agent flow modes (CAAS_AGENT_FLOW, default: hot-pool):
#   hot-pool          — legacy: agents in hardware-inventory, this script
#                       labels AND approves them.
#   cluster-namespace — agents in the ClusterOrder namespace
#                       (CAAS_CLUSTER_ORDER_NAMESPACE). This script boots the
#                       ClusterOrder's allocated virtual BMHs from its InfraEnv
#                       discovery ISO. It does NOT label or approve agents —
#                       osac ci_create owns approval.
#
# Required env:
#   CLONE_NAME   — cluster-tool clone name (used to find the libvirt network)
#   KUBECONFIG   — path to the cluster kubeconfig
#
# Optional env:
#   CAAS_AGENT_FLOW              — "hot-pool" (default) or "cluster-namespace"
#   CAAS_CLUSTER_ORDER_NAMESPACE — required when CAAS_AGENT_FLOW=cluster-namespace
#   CAAS_CLUSTER_ORDER_NAME      — parent ClusterOrder to monitor for deletion
#   OSAC_NAMESPACE               — OSAC deployment namespace (default: osac-e2e-ci)
#   OSAC_PULL_SECRET_PATH        — path to pull-secret JSON (default: $RUNNER_TEMP/pull-secret.json)
#   AGENT_HOST_COUNT             — hot-pool agent VM count (default: 2)
#   AGENT_RESOURCE_CLASS         — hot-pool resource class label (default: ci-worker)
#
# Teardown: teardown.sh cleans up hot-pool VMs by the "caas-agent-${CLONE_NAME}-"
# prefix — see the "Clean up CaaS agent VMs" section there. Cluster-namespace
# mode reuses virtual BMHs, which teardown already owns.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=.github/scripts/setup-caas-agent-flow-lib.sh
source "${SCRIPT_DIR}/setup-caas-agent-flow-lib.sh"

: "${CLONE_NAME:?CLONE_NAME is required}"
: "${KUBECONFIG:?KUBECONFIG is required}"

CAAS_AGENT_FLOW="${CAAS_AGENT_FLOW:-hot-pool}"
OSAC_NAMESPACE="${OSAC_NAMESPACE:-osac-e2e-ci}"
PULL_SECRET="${OSAC_PULL_SECRET_PATH:-${RUNNER_TEMP:-/tmp}/pull-secret.json}"
AGENT_HOST_COUNT="${AGENT_HOST_COUNT:-2}"
AGENT_RESOURCE_CLASS="${AGENT_RESOURCE_CLASS:-ci-worker}"
CAAS_CLUSTER_ORDER_NAME="${CAAS_CLUSTER_ORDER_NAME:-}"
INFRAENV_NAME="infraenv"
if [[ "${CAAS_AGENT_FLOW}" == "cluster-namespace" && -n "${CAAS_CLUSTER_ORDER_NAME}" ]]; then
    INFRAENV_NAME="${CAAS_CLUSTER_ORDER_NAME}-infraenv"
fi

VIRSH="virsh -c qemu:///system"
CT_NETWORK="test-infra-net-${CLONE_NAME}"
VM_VCPUS=4
VM_MEMORY=16384
VM_DISK_SIZE=120  # GB — Assisted needs ≥100 GB

if ! validate_agent_flow; then
    echo "ERROR: invalid CAAS_AGENT_FLOW '${CAAS_AGENT_FLOW}' (expected hot-pool or cluster-namespace)" >&2
    exit 1
fi

# Resolve target namespace based on agent flow mode.
if [[ "${CAAS_AGENT_FLOW}" == "cluster-namespace" ]]; then
    info() { echo "==> [cluster-namespace] $*"; }
    if [[ -z "${CAAS_CLUSTER_ORDER_NAMESPACE:-}" ]]; then
        info "No ClusterOrder namespace yet; skipping pre-order agent setup."
        exit 0
    fi
    if [[ -z "${CAAS_CLUSTER_ORDER_NAME}" ]]; then
        echo "WARNING: CAAS_CLUSTER_ORDER_NAME is not set; ClusterOrder deletion detection is disabled." >&2
        echo "WARNING: Set CAAS_CLUSTER_ORDER_NAME to the parent ClusterOrder so agent setup" >&2
        echo "WARNING: can detect order deletion and stop early." >&2
    fi
    AGENT_NAMESPACE="${CAAS_CLUSTER_ORDER_NAMESPACE}"
else
    AGENT_NAMESPACE="hardware-inventory"
    info() { echo "==> $*"; }
fi

# ClusterOrder-scoped agent VMs share the ClusterOrder namespace, but
# pytest-xdist can create multiple orders concurrently. Keep VM names,
# storage, and MAC addresses unique per order.
VM_IDENTITY="${CAAS_CLUSTER_ORDER_NAME:-${AGENT_NAMESPACE}}"
NAMESPACE_HASH="$(printf '%s' "${VM_IDENTITY}" | sha256sum | cut -c1-8)"
VM_PREFIX="caas-agent-${CLONE_NAME}-${NAMESPACE_HASH}"
VM_DISK_DIR="/tmp/caas-agent-disks-${CLONE_NAME}/${NAMESPACE_HASH}"
SSH_PUB_KEY="$(cat ~/.ssh/id_rsa.pub 2>/dev/null || cat ~/.ssh/id_ed25519.pub 2>/dev/null || true)"
VM_NAMES=()
BMH_MACS=()
SETUP_COMPLETED=0

order_is_terminating() {
    [[ -n "${CAAS_CLUSTER_ORDER_NAME}" ]] || return 1

    local order_json deletion_timestamp state
    if ! order_json=$(oc get clusterorder "${CAAS_CLUSTER_ORDER_NAME}" \
        -n "${OSAC_NAMESPACE}" --ignore-not-found -o json 2>/dev/null); then
        return 1
    fi
    [[ -n "${order_json}" ]] || return 0

    deletion_timestamp=$(jq -r '.metadata.deletionTimestamp // ""' <<< "${order_json}")
    state=$(jq -r '.status.state // .status.phase // ""' <<< "${order_json}")
    [[ -n "${deletion_timestamp}" || "${state}" =~ [Dd][Ee][Ll][Ee][Tt] ]]
}

namespace_is_terminating() {
    local namespace_json deletion_timestamp
    order_is_terminating && return 0
    if ! namespace_json=$(oc get namespace "${AGENT_NAMESPACE}" --ignore-not-found -o json 2>/dev/null); then
        return 1
    fi
    [[ -n "${namespace_json}" ]] || return 0
    deletion_timestamp=$(jq -r '.metadata.deletionTimestamp // ""' <<< "${namespace_json}")
    [[ -n "${deletion_timestamp}" ]]
}

cleanup_incomplete_agent_vms() {
    local rc=$? vm_name
    trap - EXIT

    if [[ "${CAAS_AGENT_FLOW}" == "cluster-namespace" && "${SETUP_COMPLETED}" -ne 1 ]]; then
        info "Agent setup ended before completion; removing per-order VMs and disks..."
        for vm_name in "${VM_NAMES[@]}"; do
            ${VIRSH} destroy "${vm_name}" >/dev/null 2>&1 || true
            ${VIRSH} undefine "${vm_name}" --nvram >/dev/null 2>&1 || true
        done
        rm -rf "${VM_DISK_DIR}"
    fi

    exit "${rc}"
}

trap 'exit 143' TERM
trap 'exit 130' INT
trap cleanup_incomplete_agent_vms EXIT

if [[ "${CAAS_AGENT_FLOW}" == "cluster-namespace" ]]; then
    if ! namespace_json=$(oc get namespace "${AGENT_NAMESPACE}" --ignore-not-found -o json 2>/dev/null); then
        echo "ERROR: Could not check ClusterOrder namespace ${AGENT_NAMESPACE}." >&2
        exit 1
    fi
    if [[ -z "${namespace_json}" ]]; then
        info "ClusterOrder namespace ${AGENT_NAMESPACE} has already been removed; skipping agent setup."
        exit 0
    fi
    if namespace_is_terminating; then
        info "ClusterOrder namespace ${AGENT_NAMESPACE} is terminating; skipping agent setup."
        exit 0
    fi
else
    info "Creating agent namespace '${AGENT_NAMESPACE}'..."
    oc create namespace "${AGENT_NAMESPACE}" --dry-run=client -o yaml | oc apply -f -
fi

stop_if_namespace_terminating() {
    if namespace_is_terminating; then
        info "ClusterOrder namespace ${AGENT_NAMESPACE} is terminating; ending agent setup."
        exit 0
    fi
}

cluster_order_worker_bmi_names() {
    local order_json expected_worker_count
    if ! order_json=$(oc get clusterorder "${CAAS_CLUSTER_ORDER_NAME}" \
        -n "${OSAC_NAMESPACE}" --ignore-not-found -o json 2>/dev/null); then
        return 1
    fi
    [[ -n "${order_json}" ]] || return 1

    expected_worker_count=$(jq '[.spec.nodeRequests[]?.numberOfNodes] | add // 0' <<< "${order_json}")
    jq -r --argjson expected "${expected_worker_count}" '
        .status.workers // []
        | map(.bareMetalInstance.name // empty)
        | if length == $expected then .[] else empty end
    ' <<< "${order_json}"
}

bmi_external_host_id() {
    local bmi_name="$1" bmi_json external_host_id
    if ! bmi_json=$(oc get bmi "${bmi_name}" -n "${OSAC_NAMESPACE}" \
        --ignore-not-found -o json 2>/dev/null); then
        return 1
    fi
    [[ -n "${bmi_json}" ]] || return 1

    external_host_id=$(jq -r '.spec.externalHostID // ""' <<< "${bmi_json}")
    [[ "${external_host_id}" == */* ]] || return 1
    printf '%s\n' "${external_host_id}"
}

redfish_request() {
    local method="$1" url="$2" body_file="$3" netrc_file="$4" timeout="$5"
    curl --noproxy '*' --silent --fail-with-body \
        --connect-timeout 5 --max-time "${timeout}" \
        --netrc-file "${netrc_file}" \
        -H 'Content-Type: application/json' \
        -X "${method}" --data "@${body_file}" \
        "${url}" >/dev/null 2>/dev/null
}

boot_allocated_virtual_bmhs() {
    local worker_bmi_names bmi_name bmi_external_id
    local bmh_namespace bmh_name bmh_json secret_name secret_json
    local bmc_address redfish_url bmc_username bmc_password bmc_host boot_mac
    local netrc_file boot_body_file iso_body_file reset_body_file
    local elapsed=0

    info "Waiting for ClusterOrder worker BareMetalInstances..."
    while true; do
        stop_if_namespace_terminating
        if worker_bmi_names=$(cluster_order_worker_bmi_names) && [[ -n "${worker_bmi_names}" ]]; then
            break
        fi
        sleep 10
        elapsed=$((elapsed + 10))
        if [[ "${elapsed}" -ge 600 ]]; then
            echo "ERROR: Timed out waiting for ClusterOrder workers after ${elapsed}s" >&2
            exit 1
        fi
    done

    readarray -t worker_bmi_names <<< "${worker_bmi_names}"
    info "Found ${#worker_bmi_names[@]} allocated worker BareMetalInstances."

    for bmi_name in "${worker_bmi_names[@]}"; do
        elapsed=0
        while true; do
            stop_if_namespace_terminating
            if bmi_external_id=$(bmi_external_host_id "${bmi_name}") && [[ -n "${bmi_external_id}" ]]; then
                break
            fi
            sleep 10
            elapsed=$((elapsed + 10))
            if [[ "${elapsed}" -ge 600 ]]; then
                echo "ERROR: Timed out waiting for BMI ${bmi_name} host allocation after ${elapsed}s" >&2
                exit 1
            fi
        done

        bmh_namespace="${bmi_external_id%/*}"
        bmh_name="${bmi_external_id#*/}"
        if ! bmh_json=$(oc get bmh "${bmh_name}" -n "${bmh_namespace}" -o json 2>/dev/null); then
            echo "ERROR: Could not read allocated BareMetalHost for BMI ${bmi_name}." >&2
            exit 1
        fi

        boot_mac=$(jq -r '.spec.bootMACAddress // ""' <<< "${bmh_json}")
        BMH_MACS+=("${boot_mac}")
        bmc_address=$(jq -r '.spec.bmc.address // ""' <<< "${bmh_json}")
        secret_name=$(jq -r '.spec.bmc.credentialsName // ""' <<< "${bmh_json}")
        redfish_url="${bmc_address#redfish-virtualmedia+}"
        if [[ -z "${boot_mac}" || -z "${secret_name}" ]] ||
            [[ "${redfish_url}" != http://* && "${redfish_url}" != https://* ]]; then
            echo "ERROR: BMI ${bmi_name} does not resolve to a bootable virtual BMH." >&2
            exit 1
        fi
        if ! secret_json=$(oc get secret "${secret_name}" -n "${bmh_namespace}" -o json 2>/dev/null); then
            echo "ERROR: Could not read BMC secret for BareMetalHost ${bmh_name}." >&2
            exit 1
        fi

        bmc_username=$(jq -r '.data.username // .stringData.username // ""' <<< "${secret_json}" | tr -d '\n')
        bmc_password=$(jq -r '.data.password // .stringData.password // ""' <<< "${secret_json}" | tr -d '\n')
        if [[ -z "${bmc_username}" || -z "${bmc_password}" ]]; then
            echo "ERROR: BareMetalHost ${bmh_name} BMC secret is incomplete." >&2
            exit 1
        fi

        netrc_file=$(mktemp "${RUNNER_TEMP:-/tmp}/caas-bmc-netrc.XXXXXX")
        boot_body_file=$(mktemp "${RUNNER_TEMP:-/tmp}/caas-redfish-boot.XXXXXX")
        iso_body_file=$(mktemp "${RUNNER_TEMP:-/tmp}/caas-redfish-iso.XXXXXX")
        reset_body_file=$(mktemp "${RUNNER_TEMP:-/tmp}/caas-redfish-reset.XXXXXX")
        chmod 600 "${netrc_file}" "${boot_body_file}" "${iso_body_file}" "${reset_body_file}"

        bmc_host=$(printf '%s\n' "${redfish_url}" | sed -E 's|^https?://||; s|[:/].*||')
        printf 'machine %s login %s password %s\n' \
            "${bmc_host}" "${bmc_username}" "${bmc_password}" > "${netrc_file}"
        printf '%s\n' '{"Boot":{"BootSourceOverrideTarget":"Cd"}}' > "${boot_body_file}"
        jq -n --arg image "${ISO_URL}" \
            '{Image:$image,Inserted:true,WriteProtected:true}' > "${iso_body_file}"
        printf '%s\n' '{"ResetType":"ForceRestart"}' > "${reset_body_file}"

        info "Booting allocated BareMetalHost ${bmh_name} from the discovery ISO..."
        if ! redfish_request PATCH "${redfish_url}" "${boot_body_file}" "${netrc_file}" 15 ||
            ! redfish_request POST "${redfish_url}/VirtualMedia/CD/Actions/VirtualMedia.InsertMedia" \
                "${iso_body_file}" "${netrc_file}" 600 ||
            ! redfish_request POST "${redfish_url}/Actions/ComputerSystem.Reset" \
                "${reset_body_file}" "${netrc_file}" 15; then
            echo "ERROR: Failed to boot BareMetalHost ${bmh_name} through Redfish." >&2
            rm -f "${netrc_file}" "${boot_body_file}" "${iso_body_file}" "${reset_body_file}"
            exit 1
        fi
        rm -f "${netrc_file}" "${boot_body_file}" "${iso_body_file}" "${reset_body_file}"
    done
}

wait_for_cluster_namespace_agents() {
    local agents_json matched elapsed=0 index
    info "Waiting for ${#BMH_MACS[@]} Agents from the allocated virtual BMHs..."
    while true; do
        stop_if_namespace_terminating
        matched=0
        if agents_json=$(oc get agent -n "${AGENT_NAMESPACE}" \
            -l "infraenvs.agent-install.openshift.io=${INFRAENV_NAME}" -o json 2>/dev/null); then
            for index in "${!BMH_MACS[@]}"; do
                if [[ "$(jq --arg mac "${BMH_MACS[$index]}" '
                    [.items[] | select(
                        ([.status.inventory.interfaces[]?.macAddress] |
                            map(ascii_downcase) |
                            index(($mac | ascii_downcase))) != null
                    )] | length
                ' <<< "${agents_json}")" -ge 1 ]]; then
                    matched=$((matched + 1))
                fi
            done
        fi
        [[ "${matched}" -eq "${#BMH_MACS[@]}" ]] && break

        sleep 30
        elapsed=$((elapsed + 30))
        echo "  ${elapsed}s elapsed — ${matched}/${#BMH_MACS[@]} allocated BMH agents registered"
        if [[ "${elapsed}" -ge 900 ]]; then
            echo "ERROR: Timed out waiting for allocated BMH agents after ${elapsed}s" >&2
            exit 1
        fi
    done
    info "All ${#BMH_MACS[@]} allocated BMH agents registered"
}

# ---------- create the agent namespace resources and InfraEnv ----------

info "Creating pull-secret in ${AGENT_NAMESPACE}..."
oc create secret generic pull-secret \
    -n "${AGENT_NAMESPACE}" \
    --from-file=.dockerconfigjson="${PULL_SECRET}" \
    --type=kubernetes.io/dockerconfigjson \
    --dry-run=client -o yaml | oc apply -f -

info "Creating CAPI provider role in ${AGENT_NAMESPACE}..."
oc apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: capi-provider-role
  namespace: ${AGENT_NAMESPACE}
rules:
- apiGroups: ["agent-install.openshift.io"]
  resources: ["agents"]
  verbs: ["*"]
EOF

info "Creating InfraEnv '${INFRAENV_NAME}' in ${AGENT_NAMESPACE}..."
oc apply -f - <<EOF
apiVersion: agent-install.openshift.io/v1beta1
kind: InfraEnv
metadata:
  name: ${INFRAENV_NAME}
  namespace: ${AGENT_NAMESPACE}
spec:
  pullSecretRef:
    name: pull-secret
  sshAuthorizedKey: "${SSH_PUB_KEY}"
EOF

info "Waiting for discovery ISO URL..."
elapsed=0
while true; do
    stop_if_namespace_terminating
    ISO_URL=$(oc get infraenv "${INFRAENV_NAME}" -n "${AGENT_NAMESPACE}" \
        -o jsonpath='{.status.isoDownloadURL}' 2>/dev/null) || true
    [[ -n "${ISO_URL}" ]] && break
    sleep 5; elapsed=$((elapsed + 5))
    if [[ "${elapsed}" -ge 300 ]]; then
        echo "ERROR: Timed out waiting for ISO URL after ${elapsed}s" >&2
        exit 1
    fi
done
# Log readiness without exposing the signed URL.
info "Discovery ISO URL ready"

# Cluster-namespace mode must reuse the BMHs allocated to the ClusterOrder so
# Agent inventory MACs match the BareMetalInstance hardware inventory.
if [[ "${CAAS_AGENT_FLOW}" == "cluster-namespace" ]]; then
    boot_allocated_virtual_bmhs
    wait_for_cluster_namespace_agents
    SETUP_COMPLETED=1
    info "setup-caas-agents complete (agent_flow=${CAAS_AGENT_FLOW})."
    exit 0
fi

# ---------- step 3: discover cluster-tool network and boot VMs ----------

info "Discovering cluster-tool network '${CT_NETWORK}'..."
if ! ${VIRSH} net-info "${CT_NETWORK}" &>/dev/null; then
    echo "ERROR: libvirt network '${CT_NETWORK}' not found." >&2
    echo "Available networks:" >&2
    ${VIRSH} net-list --all >&2
    exit 1
fi

mkdir -p "${VM_DISK_DIR}"

ISO_FILE="${VM_DISK_DIR}/discovery.iso"
info "Downloading discovery ISO..."
curl -k -L --fail-with-body -o "${ISO_FILE}" "${ISO_URL}"

OVMF_CODE="/usr/share/OVMF/OVMF_CODE.secboot.fd"
OVMF_VARS="/usr/share/OVMF/OVMF_VARS.fd"

info "Creating ${AGENT_HOST_COUNT} agent VMs on network ${CT_NETWORK}..."
for i in $(seq 1 "${AGENT_HOST_COUNT}"); do
    stop_if_namespace_terminating
    VM_NAME="${VM_PREFIX}-${i}"
    MAC="52:54:${NAMESPACE_HASH:0:2}:${NAMESPACE_HASH:2:2}:${NAMESPACE_HASH:4:2}:$(printf '%02x' "${i}")"
    DISK_PATH="${VM_DISK_DIR}/${VM_NAME}.qcow2"
    VARS_PATH="${VM_DISK_DIR}/${VM_NAME}-VARS.fd"
    VM_NAMES+=("${VM_NAME}")

    if ${VIRSH} domstate "${VM_NAME}" 2>/dev/null | grep -q "running"; then
        echo "  VM ${VM_NAME} already running — skipping"
        continue
    fi

    echo "  Creating VM: ${VM_NAME} (MAC: ${MAC})..."
    qemu-img create -f qcow2 "${DISK_PATH}" "${VM_DISK_SIZE}G"
    cp "${OVMF_VARS}" "${VARS_PATH}"

    ${VIRSH} define /dev/stdin <<VMXML
<domain type='kvm'>
  <name>${VM_NAME}</name>
  <memory unit='MiB'>${VM_MEMORY}</memory>
  <vcpu>${VM_VCPUS}</vcpu>
  <os>
    <type arch='x86_64' machine='q35'>hvm</type>
    <loader readonly='yes' type='pflash'>${OVMF_CODE}</loader>
    <nvram>${VARS_PATH}</nvram>
    <boot dev='cdrom'/>
    <boot dev='hd'/>
  </os>
  <cpu mode='host-passthrough' check='none' migratable='on'/>
  <features>
    <acpi/>
    <apic/>
  </features>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='${DISK_PATH}'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='${ISO_FILE}'/>
      <target dev='sda' bus='sata'/>
      <readonly/>
    </disk>
    <interface type='network'>
      <mac address='${MAC}'/>
      <source network='${CT_NETWORK}'/>
      <model type='virtio'/>
    </interface>
    <console type='pty'/>
  </devices>
  <seclabel type='none'/>
</domain>
VMXML

    ${VIRSH} start "${VM_NAME}"
    echo "  Started VM ${VM_NAME}: ${VM_VCPUS} vCPU, ${VM_MEMORY}MB RAM, ${VM_DISK_SIZE}GB disk"
done

info "VMs created: ${VM_NAMES[*]}"

# ---------- step 4: wait for agents, label, and conditionally approve ----------

EXPECTED_AGENTS=${AGENT_HOST_COUNT}

info "Waiting for ${EXPECTED_AGENTS} agents with inventory to register (this may take 5-10 minutes)..."
elapsed=0
while true; do
    stop_if_namespace_terminating
    # Count only agents whose inventory annotation includes a MAC
    # address. The assisted controller creates the Agent CR when the
    # host registers, but adds the inventory annotation later. Counting
    # CRs without checking for inventory causes a race: the MAC map
    # builder below reads inventory that has not arrived yet.
    count=$(oc get agent -n "${AGENT_NAMESPACE}" -o json 2>/dev/null \
        | jq '[.items[]
            | (.metadata.annotations["agent.agent-install.openshift.io/inventory"] // "")
            | fromjson? | .interfaces[0].mac_address // empty] | length' 2>/dev/null || echo 0)
    [[ "${count}" -ge "${EXPECTED_AGENTS}" ]] && break
    sleep 30; elapsed=$((elapsed + 30))
    echo "  ${elapsed}s elapsed — ${count}/${EXPECTED_AGENTS} agents with inventory"
    if [[ "${elapsed}" -ge 900 ]]; then
        echo "ERROR: Timed out waiting for agents after ${elapsed}s (${count}/${EXPECTED_AGENTS} with inventory)" >&2
        exit 1
    fi
done
info "All ${EXPECTED_AGENTS} agents registered with inventory"

if should_approve_agents; then
    info "Approving, labeling, and annotating agents..."
else
    info "Labeling and annotating agents (no approval — osac owns approval)..."
fi

AGENT_MAC_MAP=$(oc get agent -n "${AGENT_NAMESPACE}" -o json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for agent in data['items']:
    name = agent['metadata']['name']
    raw = agent['metadata'].get('annotations', {}).get('agent.agent-install.openshift.io/inventory')
    if not raw:
        continue
    ifaces = json.loads(raw).get('interfaces') or []
    if not ifaces:
        continue
    mac = ifaces[0]['mac_address']
    print(f'{name} {mac}')
")

ANNOTATED_COUNT=0
for agent in $(oc get agent -n "${AGENT_NAMESPACE}" -o jsonpath='{.items[*].metadata.name}'); do
    stop_if_namespace_terminating
    if should_approve_agents; then
        oc patch agent/"${agent}" -n "${AGENT_NAMESPACE}" --type=merge \
            -p '{"spec":{"approved":true}}'
    fi
    oc label agent/"${agent}" -n "${AGENT_NAMESPACE}" \
        "osac.openshift.io/resource_class=${AGENT_RESOURCE_CLASS}" --overwrite

    AGENT_MAC=$(echo "${AGENT_MAC_MAP}" | awk -v a="${agent}" '$1==a{print $2}')
    for vm_name in "${VM_NAMES[@]}"; do
        VM_MAC=$(${VIRSH} domiflist "${vm_name}" | awk 'NR==3{print $5}')
        if [[ "${AGENT_MAC}" == "${VM_MAC}" ]]; then
            oc annotate agent/"${agent}" -n "${AGENT_NAMESPACE}" \
                "osac.openshift.io/host_uuid=${vm_name}" --overwrite
            if should_approve_agents; then
                echo "  Approved, labeled, and annotated agent $(( ANNOTATED_COUNT + 1 ))"
            else
                echo "  Labeled and annotated agent $(( ANNOTATED_COUNT + 1 )) (no approval)"
            fi
            ANNOTATED_COUNT=$((ANNOTATED_COUNT + 1))
            break
        fi
    done
done

if [[ "${ANNOTATED_COUNT}" -ne "${EXPECTED_AGENTS}" ]]; then
    echo "ERROR: Only ${ANNOTATED_COUNT}/${EXPECTED_AGENTS} agents got host_uuid annotation (MAC matching failed)" >&2
    exit 1
fi

# Mark completion before the log line so the EXIT trap never races
# with exit-after-echo and incorrectly cleans up the VMs.
SETUP_COMPLETED=1
info "setup-caas-agents complete (agent_flow=${CAAS_AGENT_FLOW})."
