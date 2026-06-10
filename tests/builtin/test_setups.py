"""Tests for real builtin setups shipped with zaigr."""

from functools import partial

import pytest

from ..conftest import err_msg, run as _run

run = _run


def _checked_run(cmd, **kwargs):
    stdout, stderr, rc = _run(cmd, **kwargs)
    assert rc == 0, err_msg(stdout, stderr)
    return stdout


def test_fresh_project_firewall_is_debian_only(project):
    """A fresh project VM only exposes the Debian package hosts from the base image."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    run(
        f"{zaigr} project vm start --ram 2048 --cpu 2",
        input="y\n",
        timeout=180,
    )
    status = run(
        f"{zaigr} project status",
        timeout=10,
    )
    assert "status: running" in status

    output = run(
        [
            zaigr,
            "project",
            "vm",
            "exec",
            "--",
            "bash",
            "-lc",
            "test ! -e /etc/apt/apt.conf.d/99zaigr-force-ipv4 && printf 'apt-ipv6-enabled\\n'",
        ],
        timeout=10,
    )
    assert "apt-ipv6-enabled" in output

    firewall = run(
        f"{zaigr} project firewall show",
        timeout=10,
    )
    assert "deb.debian.org" in firewall
    assert "debian.map.fastlydns.net" in firewall
    assert "security.debian.org" in firewall
    assert "registry.npmjs.org" not in firewall
    assert "pypi.org" not in firewall
    assert "api.openai.com" not in firewall
    assert "claude.ai" not in firewall
    assert "go.dev" not in firewall


@pytest.mark.timeout(1200)
def test_python_setup_installs_python_and_pytest(project):
    """The builtin `python` setup installs Python and pytest in the project VM."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    run(
        f"{zaigr} project setup run python --ram 2048 --cpu 2",
        input="y\n",
        timeout=1200,
    )
    status = run(
        f"{zaigr} project status",
        timeout=10,
    )
    assert "status: running" in status

    output = run(
        f"{zaigr} project vm exec -- python3 --version",
        timeout=10,
    )
    assert "Python 3" in output

    output = run(
        f"{zaigr} project vm exec -- pytest --version",
        timeout=10,
    )
    assert "pytest " in output

    run(
        [
            zaigr,
            "project",
            "vm",
            "exec",
            "--",
            "bash",
            "-lc",
            "python3 -c 'import xdist' && pytest -q -n 1 --version",
        ],
        timeout=10,
    )

    output = run(
        f"{zaigr} project vm exec -- mypy --version",
        timeout=10,
    )
    assert "mypy " in output

    firewall = run(
        f"{zaigr} project firewall show",
        timeout=10,
    )
    assert "# python" in firewall
    assert "pypi.org" in firewall
    assert "files.pythonhosted.org" in firewall


@pytest.mark.timeout(1200)
def test_nodejs_setup_installs_node_and_npm_without_extra_firewall(project):
    """The builtin `nodejs` setup stays apt-only and installs Node.js plus npm."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    run(
        f"{zaigr} project setup run nodejs --ram 2048 --cpu 2",
        input="y\n",
        timeout=1200,
    )
    status = run(
        f"{zaigr} project status",
        timeout=10,
    )
    assert "status: running" in status

    output = run(
        f"{zaigr} project vm exec -- node --version",
        timeout=10,
    )
    assert output.startswith("v")

    output = run(
        f"{zaigr} project vm exec -- npm --version",
        timeout=10,
    )
    assert "." in output

    firewall = run(
        f"{zaigr} project firewall show",
        timeout=10,
    )
    assert "# nodejs" not in firewall
    assert "registry.npmjs.org" not in firewall


@pytest.mark.timeout(1200)
def test_go_setup_installs_go_and_golangci_lint(project):
    """The builtin `go` setup installs Go tooling in the project VM."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    run(
        f"{zaigr} project setup run go --ram 2048 --cpu 2",
        input="y\n",
        timeout=1200,
    )
    status = run(
        f"{zaigr} project status",
        timeout=10,
    )
    assert "status: running" in status

    output = run(
        f"{zaigr} project vm exec -- go version",
        timeout=10,
    )
    assert "go version go" in output

    output = run(
        f"{zaigr} project vm exec -- golangci-lint version",
        timeout=10,
    )
    assert "golangci-lint" in output

    output = run(
        f"{zaigr} project vm exec -- goreleaser --version",
        timeout=10,
    )
    assert "goreleaser" in output

    firewall = run(
        f"{zaigr} project firewall show",
        timeout=10,
    )
    assert "# go" in firewall
    assert "go.dev" in firewall
    assert "proxy.golang.org" in firewall
    assert "sum.golang.org" in firewall


@pytest.mark.timeout(2400)
def test_yocto_kas_setup_installs_kas_and_host_tools(project):
    """The builtin `yocto-kas` setup installs kas and Yocto host prerequisites."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    run(
        f"{zaigr} project setup run yocto-kas --ram 4096 --cpu 2",
        input="y\n",
        timeout=1200,
    )
    status = run(
        f"{zaigr} project status",
        timeout=10,
    )
    assert "status: running" in status

    output = run(
        f"{zaigr} project vm exec -- kas --version",
        timeout=10,
    )
    assert "kas 5.3" in output

    yocto_tools_script = """
set -eu
for tool in chrpath diffstat gawk git socat; do
    command -v "$tool" >/dev/null
done
chrpath --version
diffstat --version
gawk --version >/dev/null
socat -V >/dev/null
"""
    run(
        [
            zaigr,
            "project",
            "vm",
            "exec",
            "--",
            "bash",
            "-lc",
            yocto_tools_script,
        ],
        timeout=60,
    )

    output = run(
        f"{zaigr} project vm exec -- locale charmap",
        timeout=10,
    )
    assert "UTF-8" in output

    kas_smoke_script = """
set -eu
cat >/tmp/kas-smoke.yml <<'EOF'
header:
  version: 14
machine: qemux86-64
distro: poky
target:
  - zlib-native
repos:
  poky:
    url: https://git.yoctoproject.org/poky
    branch: scarthgap
    commit: dce4163d42f7036ea216b52b9135968d51bec4c1
    layers:
      meta:
      meta-poky:
      meta-yocto-bsp:
local_conf_header:
  smoke: |
    CONF_VERSION = "2"
EOF
rm -rf /tmp/kas-smoke-work
mkdir -p /tmp/kas-smoke-work
cd /tmp/kas-smoke-work
kas checkout /tmp/kas-smoke.yml
kas shell /tmp/kas-smoke.yml -c 'bitbake zlib-native -n'
"""
    run(
        [
            zaigr,
            "project",
            "vm",
            "exec",
            "--",
            "bash",
            "-lc",
            kas_smoke_script,
        ],
        timeout=1800,
    )


@pytest.mark.timeout(2400)
def test_k3s_setup_starts_single_node_cluster_and_runs_workload(project):
    """The builtin `k3s` setup starts a single-node cluster that can run a pod."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    run(
        f"{zaigr} project setup run k3s --ram 4096 --cpu 2",
        input="y\n",
        timeout=1800,
    )
    status = run(
        f"{zaigr} project status",
        timeout=10,
    )
    assert "status: running" in status

    k3s_smoke_script = """
set -eu

cleanup_k3s_smoke() {
    kubectl delete pod net-test --ignore-not-found --wait=true || true
    kubectl delete deployment zaigr-k3s-smoke --ignore-not-found --wait=true || true
    kubectl delete service k3s-lb-smoke --ignore-not-found || true
    kubectl delete deployment k3s-lb-smoke --ignore-not-found --wait=true || true
    kubectl delete pod k3s-storage-smoke --ignore-not-found --wait=true || true
    kubectl delete pvc k3s-storage-smoke --ignore-not-found --wait=true || true
}

diagnose_coredns() {
    kubectl get pods -n kube-system -o wide || true
    kubectl describe pod -n kube-system -l k8s-app=kube-dns || true
    kubectl logs -n kube-system -l k8s-app=kube-dns --tail=100 || true
    systemctl status k3s --no-pager || true
    journalctl -u k3s --no-pager -n 100 || true
    tail -100 /var/log/opensnitchd.log || true
}

diagnose_net_test() {
    kubectl get pod net-test -o wide || true
    kubectl get pod net-test -o jsonpath='phase={.status.phase} exit={.status.containerStatuses[0].state.terminated.exitCode} reason={.status.containerStatuses[0].state.terminated.reason}' || true
    echo
    kubectl describe pod net-test || true
    kubectl describe pod -n kube-system -l k8s-app=kube-dns || true
    kubectl logs -n kube-system -l k8s-app=kube-dns --tail=100 || true
    kubectl get pods -A -o wide || true
    kubectl get svc -A -o wide || true
    kubectl get endpoints kubernetes -o wide || true
}

trap cleanup_k3s_smoke EXIT

k3s --version | grep -q 'k3s version'
helm version --short | grep -q '^v3[.]'
kubectl get nodes | grep -q ' Ready '
kubectl wait --for=condition=Ready node --all --timeout=180s
if ! kubectl -n kube-system rollout status deployment/coredns --timeout=120s; then
    diagnose_coredns
    exit 1
fi
kubectl -n kube-system rollout status deployment/local-path-provisioner --timeout=120s
kubectl -n kube-system rollout status deployment/metrics-server --timeout=120s
kubectl -n kube-system rollout status deployment/traefik --timeout=120s
kubectl get storageclass | grep -q 'local-path.*default'
kubectl -n kube-system get svc traefik | grep -q 'LoadBalancer'
kubectl get --raw /apis/metrics.k8s.io/v1beta1/nodes >/tmp/metrics-nodes.json
grep -q 'NodeMetricsList' /tmp/metrics-nodes.json

rm -rf /tmp/zaigr-helm-smoke
helm create /tmp/zaigr-helm-smoke >/tmp/helm-create.out
helm template zaigr-helm-smoke /tmp/zaigr-helm-smoke >/tmp/helm-template.yaml
grep -q 'name: zaigr-helm-smoke' /tmp/helm-template.yaml
helm list --all-namespaces >/tmp/helm-list.out

kubectl delete pvc k3s-storage-smoke --ignore-not-found --wait=true
kubectl create -f - <<'EOF'
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: k3s-storage-smoke
spec:
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 64Mi
EOF
kubectl create -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: k3s-storage-smoke
spec:
  restartPolicy: Never
  containers:
  - name: write
    image: busybox:1.36
    command: ['sh', '-c', 'echo zaigr-storage-ok > /data/proof && cat /data/proof']
    volumeMounts:
    - name: data
      mountPath: /data
  volumes:
  - name: data
    persistentVolumeClaim:
      claimName: k3s-storage-smoke
EOF
kubectl wait --for=jsonpath='{.status.phase}'=Succeeded pod/k3s-storage-smoke --timeout=180s
kubectl logs k3s-storage-smoke | grep -q 'zaigr-storage-ok'
kubectl delete pod k3s-storage-smoke --wait=true
kubectl delete pvc k3s-storage-smoke --wait=true

kubectl delete deployment k3s-lb-smoke --ignore-not-found --wait=true
kubectl delete service k3s-lb-smoke --ignore-not-found
kubectl create deployment k3s-lb-smoke --image=nginx:alpine
kubectl expose deployment k3s-lb-smoke --port=8081 --target-port=80 --type=LoadBalancer
kubectl rollout status deployment/k3s-lb-smoke --timeout=300s
kubectl -n kube-system wait --for=condition=Ready pod -l svccontroller.k3s.cattle.io/svcname=k3s-lb-smoke --timeout=120s
kubectl get pods -A | grep 'svclb-k3s-lb-smoke.*1/1.*Running'
kubectl delete service k3s-lb-smoke
kubectl delete deployment k3s-lb-smoke --wait=true

ip route get 10.42.0.1 || true
ip route get 10.43.0.1 || true
! ip route get 10.42.0.1 2>/dev/null | grep -q ' dev eth0 '
! ip route get 10.43.0.1 2>/dev/null | grep -q ' dev eth0 '

kubectl create deployment zaigr-k3s-smoke --image=nginx:alpine
kubectl rollout status deployment/zaigr-k3s-smoke --timeout=300s
kubectl get pods -l app=zaigr-k3s-smoke | grep -q '1/1[[:space:]]*Running'
kubectl delete deployment zaigr-k3s-smoke --wait=true

kubectl delete pod net-test --ignore-not-found --wait=true
kubectl run net-test --image=curlimages/curl --restart=Never --command -- sleep 600
kubectl wait --for=condition=Ready pod/net-test --timeout=180s
if ! kubectl exec net-test -- sh -c "curl -ksS --connect-timeout 10 -o /tmp/api.out -w 'API_HTTP_STATUS=%{http_code}\\n' https://10.43.0.1/version; cat /tmp/api.out" | grep -Eq 'API_HTTP_STATUS=(200|401)'; then
    diagnose_net_test
    exit 1
fi
if ! kubectl exec net-test -- sh -c "curl -ksS --connect-timeout 10 -o /tmp/api.out -w 'API_DNS_HTTP_STATUS=%{http_code}\\n' https://kubernetes.default.svc/version; cat /tmp/api.out" | grep -Eq 'API_DNS_HTTP_STATUS=(200|401)'; then
    diagnose_net_test
    exit 1
fi
if kubectl exec net-test -- sh -c "curl -ksS --connect-timeout 5 -m 10 https://example.com >/tmp/external.out"; then
    echo "net-test pod reached external egress without an allowlist entry" >&2
    exit 1
fi
kubectl delete pod net-test --wait=true
"""
    run(
        [
            zaigr,
            "project",
            "vm",
            "exec",
            "--",
            "bash",
            "-lc",
            k3s_smoke_script,
        ],
        timeout=1800,
    )


@pytest.mark.timeout(1200)
def test_release_tools_setup_installs_release_tooling(project):
    """The builtin `release-tools` setup installs release and package-test tools."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    raw = partial(_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    stdout, stderr, rc = raw(
        f"{zaigr} project setup run release-tools --ram 2048 --cpu 2",
        input="y\n",
        timeout=1200,
    )
    assert rc == 0, err_msg(stdout, stderr)
    assert ":: Setup installation has full network access" not in stdout
    assert ":: Setup installation has full network access" not in stderr
    status = run(
        f"{zaigr} project status",
        timeout=10,
    )
    assert "status: running" in status

    output = run(
        f"{zaigr} project vm exec -- git-cliff --version",
        timeout=10,
    )
    assert "git-cliff" in output

    output = run(
        f"{zaigr} project vm exec -- nfpm --version",
        timeout=10,
    )
    assert "nfpm" in output

    package_tools_script = """
set -eu
for tool in podman fuse-overlayfs pasta slirp4netns file rpm newuidmap newgidmap; do
    command -v "$tool" >/dev/null
done
"""
    run(
        [
            zaigr,
            "project",
            "vm",
            "exec",
            "--",
            "bash",
            "-lc",
            package_tools_script,
        ],
        timeout=10,
    )

    output = run(
        [
            zaigr,
            "project",
            "vm",
            "exec",
            "--",
            "bash",
            "-lc",
            "python3 -c 'import pexpect, pytest, xdist, pyzstd'; pytest -q -n 1 --version",
        ],
        timeout=10,
    )
    assert "pytest " in output

    run(
        f"{zaigr} project vm exec -- podman run --rm hello-world",
        timeout=600,
    )

    firewall = run(
        f"{zaigr} project firewall show",
        timeout=10,
    )
    assert "# release-tools" in firewall
    assert "github.com" in firewall
    assert "objects.githubusercontent.com" in firewall
    assert "github-releases.githubusercontent.com" in firewall
    assert "release-assets.githubusercontent.com" in firewall
    assert "auth.docker.io" in firewall
    assert "registry-1.docker.io" in firewall
    assert "docker-images-prod.6aa30f8b08e16409b46e0173d6de2f56.r2.cloudflarestorage.com" in firewall
    assert "deb.debian.org" in firewall
    assert "archive.ubuntu.com" in firewall
    assert "registry.fedoraproject.org" in firewall
    assert "download.fedoraproject.org" in firewall
    assert "geo.mirror.pkgbuild.com" in firewall


@pytest.mark.timeout(1200)
def test_codex_setup_installs_codex_and_records_firewall(project):
    """The builtin `codex` setup installs Codex and records its firewall requirements."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    run(
        f"{zaigr} project setup run codex --ram 2048 --cpu 2",
        input="y\n",
        timeout=1200,
    )
    status = run(
        f"{zaigr} project status",
        timeout=10,
    )
    assert "status: running" in status

    output = run(
        f"{zaigr} project vm exec -- codex --version",
        timeout=10,
    )
    assert "codex" in output.lower()

    firewall = run(
        f"{zaigr} project firewall show",
        timeout=10,
    )
    assert "# codex" in firewall
    assert "registry.npmjs.org" in firewall
    assert "api.openai.com" in firewall


@pytest.mark.timeout(1200)
def test_claude_setup_installs_claude(project):
    """The builtin `claude` setup installs the Claude CLI in the project VM."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    run(
        f"{zaigr} project setup run claude --ram 2048 --cpu 2",
        input="y\n",
        timeout=1200,
    )
    status = run(
        f"{zaigr} project status",
        timeout=10,
    )
    assert "status: running" in status
    assert "config: cpu=2, ram=2048MB" in status

    output = run(
        f"{zaigr} project vm exec -- claude --version",
        timeout=60,
    )
    assert "claude" in output.lower()

    firewall = run(
        f"{zaigr} project firewall show",
        timeout=10,
    )
    assert "# claude" in firewall
    assert "claude.ai" in firewall
    assert "api.anthropic.com" in firewall
