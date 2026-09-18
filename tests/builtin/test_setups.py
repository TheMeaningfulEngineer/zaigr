"""Tests for real builtin setups shipped with zaigr."""

from functools import partial
from textwrap import dedent

import pytest

from ..conftest import err_msg
from ..conftest import run as _run

run = _run


def _checked_run(cmd, **kwargs):
    stdout, stderr, rc = _run(cmd, **kwargs)
    assert rc == 0, err_msg(stdout, stderr)
    return stdout


@pytest.mark.timeout(10800)
def test_all_builtin_setups_coexist(project):
    """All builtin setups install and remain usable in one cumulative VM."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    raw = partial(_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    run(
        f"{zaigr} project vm start --ram 4096 --cpu 2",
        input="y\n",
        timeout=180,
    )
    status = run(
        f"{zaigr} project status",
        timeout=10,
    )
    assert "status: running" in status

    output = run(
        f"{zaigr} project vm exec -- readlink /bin",
        timeout=10,
    )
    assert output.strip() == "usr/bin"
    output = run(
        f"{zaigr} project vm exec -- readlink /sbin",
        timeout=10,
    )
    assert output.strip() == "usr/sbin"
    output = run(
        f"{zaigr} project vm exec -- readlink /lib",
        timeout=10,
    )
    assert output.strip() == "usr/lib"

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

    run(
        f"{zaigr} project vm exec -- "
        "curl -4 -sS -o /dev/null --connect-timeout 10 --max-time 20 "
        "http://deb.debian.org/debian/dists/trixie/InRelease",
        timeout=30,
    )
    run(
        f"{zaigr} project vm exec -- "
        "curl -4 -sS -o /dev/null --connect-timeout 10 --max-time 20 "
        "http://security.debian.org/debian-security/dists/trixie-security/InRelease",
        timeout=30,
    )
    stdout, stderr, rc = raw(
        f"{zaigr} project vm exec -- "
        "curl -4 -sS -o /dev/null --connect-timeout 3 --max-time 8 "
        "https://registry.npmjs.org",
        timeout=20,
    )
    assert rc == 28, err_msg(stdout, stderr)
    stdout, stderr, rc = raw(
        f"{zaigr} project vm exec -- "
        "curl -4 -sS -o /dev/null --connect-timeout 3 --max-time 8 https://pypi.org",
        timeout=20,
    )
    assert rc == 28, err_msg(stdout, stderr)
    stdout, stderr, rc = raw(
        f"{zaigr} project vm exec -- "
        "curl -4 -sS -o /dev/null --connect-timeout 3 --max-time 8 "
        "https://api.openai.com",
        timeout=20,
    )
    assert rc == 28, err_msg(stdout, stderr)
    stdout, stderr, rc = raw(
        f"{zaigr} project vm exec -- "
        "curl -4 -sS -o /dev/null --connect-timeout 3 --max-time 8 https://claude.ai",
        timeout=20,
    )
    assert rc == 28, err_msg(stdout, stderr)
    stdout, stderr, rc = raw(
        f"{zaigr} project vm exec -- "
        "curl -4 -sS -o /dev/null --connect-timeout 3 --max-time 8 https://go.dev",
        timeout=20,
    )
    assert rc == 28, err_msg(stdout, stderr)

    # Python
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    run(
        f"{zaigr} project setup run python",
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

    run(
        f"{zaigr} project vm exec -- "
        "curl -4 -sS -o /dev/null --connect-timeout 3 --max-time 8 https://pypi.org",
        timeout=20,
    )
    run(
        f"{zaigr} project vm exec -- "
        "curl -4 -sS -o /dev/null --connect-timeout 3 --max-time 8 "
        "https://files.pythonhosted.org",
        timeout=20,
    )

    # Node.js
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    raw = partial(_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    run(
        f"{zaigr} project setup run nodejs",
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

    stdout, stderr, rc = raw(
        f"{zaigr} project vm exec -- "
        "curl -4 -sS -o /dev/null --connect-timeout 3 --max-time 8 "
        "https://registry.npmjs.org",
        timeout=20,
    )
    assert rc == 28, err_msg(stdout, stderr)

    # Go
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    run(
        f"{zaigr} project setup run go",
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

    run(
        f"{zaigr} project vm exec -- "
        "curl -4 -sS -o /dev/null --connect-timeout 3 --max-time 8 https://go.dev",
        timeout=20,
    )
    run(
        f"{zaigr} project vm exec -- "
        "curl -4 -sS -o /dev/null --connect-timeout 3 --max-time 8 "
        "https://proxy.golang.org",
        timeout=20,
    )
    run(
        f"{zaigr} project vm exec -- "
        "curl -4 -sS -o /dev/null --connect-timeout 3 --max-time 8 "
        "https://sum.golang.org",
        timeout=20,
    )

    # Yocto/kas
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    run(
        f"{zaigr} project setup run yocto-kas",
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

    # Docker after k3s
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    vm = f"{zaigr} project vm exec --"

    run(f"{zaigr} project setup run k3s", timeout=1800)
    run(f"{zaigr} project setup run docker", timeout=1800)

    output = run(f"{vm} docker run --rm hello-world", timeout=600)
    assert "Hello from Docker!" in output

    build_dir = "/tmp/zaigr-docker-build-test"
    message = "hello from zaigr docker build\n"
    run(f"{vm} rm -rf {build_dir}")
    run(f"{vm} mkdir -p {build_dir}")
    run(f"{vm} tee {build_dir}/message.txt", input=message)
    run(
        f"{vm} tee {build_dir}/Dockerfile",
        input=dedent("""\
            FROM docker.io/library/busybox:stable
            COPY message.txt /message.txt
            CMD ["cat", "/message.txt"]
        """),
    )
    run(
        f"{vm} docker build --no-cache -t zaigr-docker-build-test {build_dir}",
        timeout=600,
    )
    output = run(f"{vm} docker run --rm zaigr-docker-build-test", timeout=600)
    assert output == message

    run(
        f"{vm} k3s kubectl wait --for=condition=Ready node --all --timeout=30s",
        timeout=40,
    )
    run(
        f"{vm} k3s kubectl delete pod docker-k3s-network "
        "--ignore-not-found --wait=true",
        timeout=30,
    )
    run(
        f"{vm} k3s kubectl run docker-k3s-network --image=curlimages/curl "
        "--restart=Never --command -- sleep 120",
        timeout=30,
    )
    run(
        f"{vm} k3s kubectl wait --for=condition=Ready pod/docker-k3s-network "
        "--timeout=180s",
        timeout=190,
    )
    run(
        [
            zaigr,
            "project",
            "vm",
            "exec",
            "--",
            "bash",
            "-lc",
            "k3s kubectl exec docker-k3s-network -- sh -c \"curl -ksS --connect-timeout 10 -o /tmp/api.out -w 'API_DNS_HTTP_STATUS=%{http_code}\\n' https://kubernetes.default.svc/version; cat /tmp/api.out\" | grep -Eq 'API_DNS_HTTP_STATUS=(200|401)'",
        ],
        timeout=30,
    )
    run(
        f"{vm} k3s kubectl delete pod docker-k3s-network --wait=true",
        timeout=60,
    )

    # Podman
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    vm = f"{zaigr} project vm exec --"

    run(f"{zaigr} project setup run podman", timeout=1800)
    run(f"{vm} podman pull docker.io/library/hello-world", timeout=600)
    output = run(
        f"{vm} podman run --rm docker.io/library/hello-world",
        timeout=600,
    )
    assert "Hello from Docker!" in output

    build_dir = "/tmp/zaigr-podman-build-test"
    message = "hello from zaigr podman build\n"
    run(f"{vm} rm -rf {build_dir}")
    run(f"{vm} mkdir -p {build_dir}")
    run(f"{vm} tee {build_dir}/message.txt", input=message)
    run(
        f"{vm} tee {build_dir}/Dockerfile",
        input=dedent("""\
            FROM docker.io/library/busybox:stable
            COPY message.txt /message.txt
            CMD ["cat", "/message.txt"]
        """),
    )
    run(
        f"{vm} podman build --no-cache -t zaigr-podman-build-test {build_dir}",
        timeout=600,
    )
    output = run(f"{vm} podman run --rm zaigr-podman-build-test", timeout=600)
    assert output == message

    # Kernel/mmdebstrap image-building tools
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    run(
        f"{zaigr} project setup run kernel-mmdebstrap",
        timeout=1200,
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
            'for tool in mmdebstrap qemu-system-x86_64 qemu-img fakeroot; do command -v "$tool"; done',
        ],
        timeout=10,
    )
    assert "mmdebstrap" in output
    assert "qemu-system-x86_64" in output

    # k3s idempotence and full workload smoke
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    run(
        f"{zaigr} project setup run k3s",
        timeout=1800,
    )
    run(
        f"{zaigr} project vm exec --root -- systemctl stop k3s",
        input="y\n",
        timeout=30,
    )
    run(
        f"{zaigr} project setup run k3s --force",
        timeout=1800,
    )
    status = run(
        f"{zaigr} project status",
        timeout=10,
    )
    assert "status: running" in status
    run(
        f"{zaigr} project vm exec -- k3s kubectl wait "
        "--for=condition=Ready node --all --timeout=30s",
        timeout=40,
    )

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

    # Release tools
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    raw = partial(_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    stdout, stderr, rc = raw(
        f"{zaigr} project setup run release-tools",
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

    run(
        f"{zaigr} project vm exec -- "
        "curl -4 -sS -o /dev/null --connect-timeout 3 --max-time 8 https://github.com",
        timeout=20,
    )
    run(
        f"{zaigr} project vm exec -- "
        "curl -4 -sS -o /dev/null --connect-timeout 3 --max-time 8 "
        "https://objects.githubusercontent.com",
        timeout=20,
    )
    run(
        f"{zaigr} project vm exec -- "
        "curl -4 -sS -o /dev/null --connect-timeout 3 --max-time 8 "
        "https://github-releases.githubusercontent.com",
        timeout=20,
    )
    run(
        f"{zaigr} project vm exec -- "
        "curl -4 -sS -o /dev/null --connect-timeout 3 --max-time 8 "
        "https://release-assets.githubusercontent.com",
        timeout=20,
    )
    run(
        f"{zaigr} project vm exec -- "
        "curl -4 -sS -o /dev/null --connect-timeout 3 --max-time 8 "
        "https://docker-images-prod.6aa30f8b08e16409b46e0173d6de2f56.r2.cloudflarestorage.com",
        timeout=20,
    )
    run(
        f"{zaigr} project vm exec -- "
        "curl -4 -sS -o /dev/null --connect-timeout 3 --max-time 8 "
        "https://archive.ubuntu.com",
        timeout=20,
    )
    run(
        f"{zaigr} project vm exec -- "
        "curl -4 -sS -o /dev/null --connect-timeout 3 --max-time 8 "
        "https://registry.fedoraproject.org",
        timeout=20,
    )
    run(
        f"{zaigr} project vm exec -- "
        "curl -4 -sS -o /dev/null --connect-timeout 3 --max-time 8 "
        "https://download.fedoraproject.org",
        timeout=20,
    )
    run(
        f"{zaigr} project vm exec -- "
        "curl -4 -sS -o /dev/null --connect-timeout 3 --max-time 8 "
        "--retry 3 --retry-all-errors --retry-delay 1 "
        "http://geo.mirror.pkgbuild.com",
        timeout=45,
    )

    # Codex
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    run(
        f"{zaigr} project setup run codex",
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

    run(
        f"{zaigr} project vm exec -- "
        "curl -4 -sS -o /dev/null --connect-timeout 3 --max-time 8 "
        "https://api.openai.com",
        timeout=20,
    )
    run(
        f"{zaigr} project vm exec -- "
        "curl -4 -sS -o /dev/null --connect-timeout 3 --max-time 8 "
        "https://registry.npmjs.org",
        timeout=20,
    )

    # Mistral
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    run(
        f"{zaigr} project setup run mistral",
        timeout=1200,
    )
    status = run(
        f"{zaigr} project status",
        timeout=10,
    )
    assert "status: running" in status

    output = run(
        f"{zaigr} project vm exec -- vibe --version",
        timeout=60,
    )
    assert "vibe" in output.lower()

    # Claude
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin

    run(
        f"{zaigr} project setup run claude",
        timeout=1200,
    )
    status = run(
        f"{zaigr} project status",
        timeout=10,
    )
    assert "status: running" in status
    assert "config: cpu=2, ram=4096MB" in status

    output = run(
        f"{zaigr} project vm exec -- claude --version",
        timeout=60,
    )
    assert "claude" in output.lower()

    run(
        f"{zaigr} project vm exec -- "
        "curl -4 -sS -o /dev/null --connect-timeout 3 --max-time 8 https://claude.ai",
        timeout=20,
    )
    run(
        f"{zaigr} project vm exec -- "
        "curl -4 -sS -o /dev/null --connect-timeout 3 --max-time 8 "
        "https://api.anthropic.com",
        timeout=20,
    )

    # Final cumulative health check
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    vm = f"{zaigr} project vm exec --"

    output = run(f"{zaigr} project setup list --applied", timeout=10)
    for setup in [
        "claude",
        "codex",
        "docker",
        "go",
        "k3s",
        "kernel-mmdebstrap",
        "mistral",
        "nodejs",
        "podman",
        "python",
        "release-tools",
        "yocto-kas",
    ]:
        assert setup in output

    output = run(f"{vm} docker run --rm hello-world", timeout=600)
    assert "Hello from Docker!" in output
    output = run(
        f"{vm} podman run --rm docker.io/library/hello-world",
        timeout=600,
    )
    assert "Hello from Docker!" in output
    run(
        f"{vm} k3s kubectl wait --for=condition=Ready node --all --timeout=30s",
        timeout=40,
    )
