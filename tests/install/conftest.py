import os

import pytest

from tests.install.cloudvm import DISTROS, _artifact_provenance
from tests.install.cloudvm import cloudvm_factory as cloudvm_factory  # noqa: PLC0414 - pytest fixture re-export


def _selected_distros():
    raw = os.environ.get("CLOUDVM_DISTROS", "")
    if not raw.strip():
        return tuple(DISTROS)
    selected = tuple(part.strip() for part in raw.split(",") if part.strip())
    invalid = [distro for distro in selected if distro not in DISTROS]
    if invalid:
        pytest.fail(
            "Invalid CLOUDVM_DISTROS value(s): " + ", ".join(invalid)
            + "; choose from: " + ", ".join(DISTROS),
            pytrace=False,
        )
    if not selected:
        pytest.fail("CLOUDVM_DISTROS must name at least one distro", pytrace=False)
    duplicates = sorted({distro for distro in selected if selected.count(distro) > 1})
    if duplicates:
        pytest.fail("CLOUDVM_DISTROS contains duplicates: " + ", ".join(duplicates), pytrace=False)
    return selected


CLOUDVM_DISTROS = _selected_distros()


def pytest_report_header(config):
    lines = ["Cloud-VM install artifacts (selected before VM setup):"]
    for label, standalone in (("standalone", True), ("Debian package", False)):
        try:
            provenance = _artifact_provenance(standalone)
        except (pytest.fail.Exception, OSError) as error:
            provenance = f"unavailable ({error})"
        lines.append(f"  {label}: {provenance}")
    return lines


@pytest.fixture
def cloudvm_distro(request):
    return request.param


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    images = getattr(item, "_cloudvm_images", {})
    if images:
        lines = [f"{distro}: sha256:{digest}" for distro, digest in sorted(images.items())]
        report.sections.append(("Cloud image checksums", "\n".join(lines)))
    artifacts = getattr(item, "_cloudvm_artifacts", {})
    if artifacts:
        lines = [f"{distro}: {details}" for distro, details in sorted(artifacts.items())]
        report.sections.append(("Cloud-VM install artifact provenance", "\n".join(lines)))
    if report.failed:
        vms = getattr(item, "_cloudvms", [])
        tails = []
        for vm in vms:
            try:
                diagnostics = vm.collect_failure_diagnostics()
            except Exception as error:  # noqa: BLE001 - diagnostics must not obscure the test failure
                diagnostics = f"failure diagnostics unavailable ({type(error).__name__})"
            try:
                serial = "".join(vm.serial_log.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)[-80:])
            except OSError as error:
                serial = f"(serial log unavailable: {error})"
            tails.append(f"{vm.distro} {diagnostics}")
            tails.append(f"{vm.distro} serial log tail:\n{serial or '(empty)'}")
        if tails:
            report.sections.append(("Cloud VM serial logs", "\n\n".join(tails)))
