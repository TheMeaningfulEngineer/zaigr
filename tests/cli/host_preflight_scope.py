"""Process-scoped Linux fixture for the Ubuntu user-namespace denial tests.

The runner needs permission to create user and mount namespaces, and libseccomp
must be installed. The fixture presents a private Ubuntu host identity and
AppArmor restriction value, then denies namespace creation only to the exec'd
CLI process. It does not change host policy, sysctls, or mount table. A host
that blocks this Python fixture's own user namespace cannot run the simulation
without separately permitting the test runner.
"""

import ctypes
import ctypes.util
import errno
import os
import pathlib
import sys

CLONE_NEWUSER = 0x10000000
CLONE_NEWNET = 0x40000000
CLONE_NEWNS = 0x00020000
MS_REC = 16384
MS_PRIVATE = 1 << 18
SCMP_ACT_ALLOW = 0x7FFF0000
SCMP_CMP_MASKED_EQ = 7
PR_SET_NO_NEW_PRIVS = 38


class SeccompArgCmp(ctypes.Structure):
    _fields_ = [
        ("arg", ctypes.c_uint),
        ("op", ctypes.c_int),
        ("datum_a", ctypes.c_uint64),
        ("datum_b", ctypes.c_uint64),
    ]


def _fail(message):
    raise OSError(message)


def _check(result, operation):
    if result == -1:
        error = ctypes.get_errno()
        _fail(f"{operation}: {os.strerror(error)}")


def _check_seccomp(result, operation):
    if result < 0:
        _fail(f"{operation}: {os.strerror(-result)}")


def _write(path, value):
    pathlib.Path(path).write_text(value, encoding="ascii")


def _unshare(libc, flags):
    _check(libc.unshare(flags), "unshare")


def _mount(libc, source, target, flags):
    source_arg = os.fsencode(source) if source is not None else None
    target_arg = os.fsencode(target)
    _check(libc.mount(source_arg, target_arg, None, flags, None), f"mount {target}")


def _map_user_namespace(libc, namespace_uid, parent_uid, namespace_gid, parent_gid):
    _unshare(libc, CLONE_NEWUSER)
    _write("/proc/self/setgroups", "deny\n")
    _write("/proc/self/uid_map", f"{namespace_uid} {parent_uid} 1\n")
    _write("/proc/self/gid_map", f"{namespace_gid} {parent_gid} 1\n")
    _check(libc.setresgid(namespace_gid, namespace_gid, namespace_gid), "setresgid")
    _check(libc.setresuid(namespace_uid, namespace_uid, namespace_uid), "setresuid")


def _install_denial_filter():
    library = ctypes.util.find_library("seccomp")
    if not library:
        _fail("libseccomp is required to install the process-scoped test filter")
    seccomp = ctypes.CDLL(library, use_errno=True)
    seccomp.seccomp_init.argtypes = [ctypes.c_uint32]
    seccomp.seccomp_init.restype = ctypes.c_void_p
    seccomp.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    seccomp.seccomp_syscall_resolve_name.restype = ctypes.c_int
    seccomp.seccomp_rule_add_array.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint,
        ctypes.POINTER(SeccompArgCmp),
    ]
    seccomp.seccomp_rule_add_array.restype = ctypes.c_int
    seccomp.seccomp_load.argtypes = [ctypes.c_void_p]
    seccomp.seccomp_load.restype = ctypes.c_int
    seccomp.seccomp_release.argtypes = [ctypes.c_void_p]

    context = seccomp.seccomp_init(SCMP_ACT_ALLOW)
    if not context:
        _fail("seccomp_init failed")
    try:
        deny = 0x00050000 | errno.EPERM
        for syscall_name in (b"clone", b"unshare"):
            syscall_number = seccomp.seccomp_syscall_resolve_name(syscall_name)
            if syscall_number < 0:
                _fail(f"libseccomp does not recognize {syscall_name.decode()}")
            for flag in (CLONE_NEWUSER, CLONE_NEWNET):
                comparison = SeccompArgCmp(0, SCMP_CMP_MASKED_EQ, flag, flag)
                result = seccomp.seccomp_rule_add_array(
                    context,
                    deny,
                    syscall_number,
                    1,
                    ctypes.byref(comparison),
                )
                _check_seccomp(result, f"add {syscall_name.decode()} seccomp rule")
        # Go can fall back to clone(2) when clone3 reports ENOSYS. Denying all
        # clone3 requests avoids an uninspectable pointer escaping the fixture.
        clone3 = seccomp.seccomp_syscall_resolve_name(b"clone3")
        if clone3 < 0:
            _fail("libseccomp does not recognize clone3")
        result = seccomp.seccomp_rule_add_array(
            context,
            0x00050000 | errno.ENOSYS,
            clone3,
            0,
            None,
        )
        _check_seccomp(result, "add clone3 seccomp rule")

        libc = ctypes.CDLL(None, use_errno=True)
        _check(libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), "set no-new-privileges")
        _check_seccomp(seccomp.seccomp_load(context), "load seccomp filter")
    finally:
        seccomp.seccomp_release(context)


def main():
    if len(sys.argv) < 5 or sys.argv[3] != "--":
        _fail("usage: host_preflight_scope.py OS_RELEASE KERNEL_DIR -- COMMAND [ARGS...]")
    if os.geteuid() == 0:
        _fail("run the simulated host fixture as an unprivileged account")

    libc = ctypes.CDLL(None, use_errno=True)
    libc.unshare.argtypes = [ctypes.c_int]
    libc.mount.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_ulong,
        ctypes.c_void_p,
    ]
    libc.setresuid.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_uint]
    libc.setresgid.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_uint]
    libc.prctl.restype = ctypes.c_int

    host_uid = os.getuid()
    host_gid = os.getgid()
    _map_user_namespace(libc, 0, host_uid, 0, host_gid)
    _unshare(libc, CLONE_NEWNS)
    _mount(libc, None, "/", MS_REC | MS_PRIVATE)

    os_release_target = pathlib.Path("/etc/os-release").resolve()
    _mount(libc, sys.argv[1], os_release_target, 4096)
    _mount(libc, sys.argv[2], "/proc/sys/kernel", 4096)

    # The nested user namespace maps its non-root identity to the caller in
    # this private namespace. The CLI therefore runs as a normal user while
    # retaining access to the caller-owned project fixture.
    _map_user_namespace(libc, host_uid, 0, host_gid, 0)
    _install_denial_filter()
    command = sys.argv[4:]
    os.execv(command[0], command)


if __name__ == "__main__":
    try:
        main()
    except OSError as error:
        print(f"host preflight fixture setup failed: {error}", file=sys.stderr)
        raise SystemExit(125)
