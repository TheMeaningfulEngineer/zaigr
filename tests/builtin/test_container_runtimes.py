"""Acceptance tests for builtin container runtime setups."""

from functools import partial
from textwrap import dedent

import pytest

from ..conftest import err_msg, run


RUNTIMES = ("docker", "podman")


def _checked_run(cmd, **kwargs):
    stdout, stderr, returncode = run(cmd, **kwargs)
    assert returncode == 0, err_msg(stdout, stderr)
    return stdout


@pytest.mark.timeout(1800)
@pytest.mark.parametrize("runtime", RUNTIMES)
def test_container_runtime_runs_hello_world_from_docker_hub(project, runtime):
    """Container runtimes pull and run hello-world."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    vm = f"{zaigr} project vm exec --"
    hello_world = "docker.io/library/hello-world"

    run(
        f"{zaigr} project setup run {runtime} --ram 2048 --cpu 2",
        input="y\n",
        timeout=1800,
    )
    run(f"{vm} {runtime} pull {hello_world}", timeout=600)
    output = run(f"{vm} {runtime} run --rm {hello_world}", timeout=600)
    assert "Hello from Docker!" in output

    build_dir = "/tmp/zaigr-basic-build-test"
    message = f"hello from zaigr {runtime} build\n"

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
        f"{vm} {runtime} build --no-cache -t zaigr-basic-build-test {build_dir}",
        timeout=600,
    )
    output = run(f"{vm} {runtime} run --rm zaigr-basic-build-test", timeout=600)
    assert output == message


@pytest.mark.timeout(1800)
def test_docker_setup_activates_in_running_project_vm(project):
    """Applying Docker to a running VM makes Docker usable without restarting."""
    run = partial(_checked_run, cwd=project.cwd, env=project.env)
    zaigr = project.zaigr_bin
    vm = f"{zaigr} project vm exec --"

    run(f"{zaigr} project vm start --ram 2048 --cpu 2", input="y\n", timeout=1800)
    run(f"{zaigr} project setup run docker", timeout=1800)
    output = run(f"{vm} docker run --rm hello-world", timeout=600)
    assert "Hello from Docker!" in output

    build_dir = "/tmp/zaigr-basic-build-test"
    message = "hello from zaigr docker build\n"

    run(f"{vm} rm -rf {build_dir}")
    run(f"{vm} mkdir -p {build_dir}")
    run(f"{vm} tee {build_dir}/message.txt", input=message)
    run(
        f"{vm} tee {build_dir}/Dockerfile",
        input=dedent("""\
            FROM busybox:stable
            COPY message.txt /message.txt
            CMD ["cat", "/message.txt"]
        """),
    )
    run(
        f"{vm} docker build --no-cache -t zaigr-basic-build-test {build_dir}",
        timeout=600,
    )
    output = run(f"{vm} docker run --rm zaigr-basic-build-test", timeout=600)
    assert output == message
