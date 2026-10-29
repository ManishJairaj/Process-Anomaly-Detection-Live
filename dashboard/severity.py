#!/usr/bin/env python3
"""
severity.py — Rule-Based Alert Severity Classification and Security Triage Engine (Stage 22)

Implements an explainable, deterministic rule-based security classification system
for system call 3-gram anomalies detected by the eBPF monitoring pipeline.

Severity Levels:
- CRITICAL: Strongly corroborated security-sensitive behavior (e.g. privilege changes,
            code injection, kernel modification, or execution combined with network).
- HIGH:     Anomalous sequences containing security-sensitive primitives (process execution,
            process tracing, network sockets, termination signals, or file permission changes).
- MEDIUM:   Suspicious sequences without verified high-risk primitives (unseen transitions,
            filesystem alterations, or anomalous memory/IPC operations).
- LOW:      Marginal anomalies consisting purely of routine I/O, polling, or time operations.

Precedence Order: CRITICAL > HIGH > MEDIUM > LOW
"""

import sys
import platform
from typing import Dict, Any, List, Set, Tuple, Optional

RULE_ENGINE_VERSION = "1.0.0"

# ==============================================================================
# 1. Linux x86_64 Architecture-Aware Syscall Mapping Table
# ==============================================================================
# Verified mapping for the standard Linux x86_64 ABI matching src/explanation.c
# and /usr/include/asm/unistd_64.h.
X86_64_SYSCALL_MAP: Dict[int, str] = {
    0: "read", 1: "write", 2: "open", 3: "close", 4: "stat", 5: "fstat",
    6: "lstat", 7: "poll", 8: "lseek", 9: "mmap", 10: "mprotect", 11: "munmap",
    12: "brk", 13: "rt_sigaction", 14: "rt_sigprocmask", 15: "rt_sigreturn",
    16: "ioctl", 17: "pread64", 18: "pwrite64", 19: "readv", 20: "writev",
    21: "access", 22: "pipe", 23: "select", 24: "sched_yield", 25: "mremap",
    26: "msync", 27: "mincore", 28: "madvise", 29: "shmget", 30: "shmat",
    31: "shmctl", 32: "dup", 33: "dup2", 34: "pause", 35: "nanosleep",
    36: "getitimer", 37: "alarm", 38: "setitimer", 39: "getpid", 40: "sendfile",
    41: "socket", 42: "connect", 43: "accept", 44: "sendto", 45: "recvfrom",
    46: "sendmsg", 47: "recvmsg", 48: "shutdown", 49: "bind", 50: "listen",
    51: "getsockname", 52: "getpeername", 53: "socketpair", 54: "setsockopt",
    55: "getsockopt", 56: "clone", 57: "fork", 58: "vfork", 59: "execve",
    60: "exit", 61: "wait4", 62: "kill", 63: "uname", 64: "semget",
    65: "semop", 66: "semctl", 67: "shmdt", 68: "msgget", 69: "msgsnd",
    70: "msgrcv", 71: "msgctl", 72: "fcntl", 73: "flock", 74: "fsync",
    75: "fdatasync", 76: "truncate", 77: "ftruncate", 78: "getdents",
    79: "getcwd", 80: "chdir", 81: "fchdir", 82: "rename", 83: "mkdir",
    84: "rmdir", 85: "creat", 86: "link", 87: "unlink", 88: "symlink",
    89: "readlink", 90: "chmod", 91: "fchmod", 92: "chown", 93: "fchown",
    94: "lchown", 95: "umask", 96: "gettimeofday", 97: "getrlimit",
    98: "getrusage", 99: "sysinfo", 100: "times", 101: "ptrace", 102: "getuid",
    103: "syslog", 104: "getgid", 105: "setuid", 106: "setgid", 107: "geteuid",
    108: "getegid", 109: "setpgid", 110: "getppid", 111: "getpgrp",
    112: "setsid", 113: "setreuid", 114: "setregid", 115: "getgroups",
    116: "setgroups", 117: "setresuid", 118: "getresuid", 119: "setresgid",
    120: "getresgid", 121: "getpgid", 122: "setfsuid", 123: "setfsgid",
    124: "getsid", 125: "capget", 126: "capset", 127: "rt_sigpending",
    128: "rt_sigtimedwait", 129: "rt_sigqueueinfo", 130: "rt_sigsuspend",
    131: "sigaltstack", 132: "utime", 133: "mknod", 134: "uselib",
    135: "personality", 136: "ustat", 137: "statfs", 138: "fstatfs",
    139: "sysfs", 140: "getpriority", 141: "setpriority", 142: "sched_setparam",
    143: "sched_getparam", 144: "sched_setscheduler", 145: "sched_getscheduler",
    146: "sched_get_priority_max", 147: "sched_get_priority_min",
    148: "sched_rr_get_interval", 149: "mlock", 150: "munlock",
    151: "mlockall", 152: "munlockall", 153: "vhangup", 154: "modify_ldt",
    155: "pivot_root", 156: "_sysctl", 157: "prctl", 158: "arch_prctl",
    159: "adjtimex", 160: "setrlimit", 161: "chroot", 162: "sync",
    163: "acct", 164: "settimeofday", 165: "mount", 166: "umount2",
    167: "swapon", 168: "swapoff", 169: "reboot", 170: "sethostname",
    171: "setdomainname", 172: "iopl", 173: "ioperment", 174: "create_module",
    175: "init_module", 176: "delete_module", 177: "get_kernel_syms",
    178: "query_module", 179: "quotactl", 180: "nfsservctl", 181: "getpmsg",
    182: "putpmsg", 183: "afs_syscall", 184: "tuxcall", 185: "security",
    186: "gettid", 187: "readahead", 188: "setxattr", 189: "lsetxattr",
    190: "fsetxattr", 191: "getxattr", 192: "lgetxattr", 193: "fgetxattr",
    194: "listxattr", 195: "llistxattr", 196: "flistxattr", 197: "removexattr",
    198: "lremovexattr", 199: "fremovexattr", 200: "tkill", 201: "time",
    202: "futex", 203: "sched_setaffinity", 204: "sched_getaffinity",
    205: "set_thread_area", 206: "io_setup", 207: "io_destroy",
    208: "io_getevents", 209: "io_submit", 210: "io_cancel",
    211: "get_thread_area", 212: "lookup_dcookie", 213: "epoll_create",
    214: "epoll_ctl_old", 215: "epoll_wait_old", 216: "remap_file_pages",
    217: "getdents64", 218: "set_tid_address", 219: "restart_syscall",
    220: "semtimedop", 221: "fadvise64", 222: "timer_create",
    223: "timer_settime", 224: "timer_gettime", 225: "timer_getoverrun",
    226: "timer_delete", 227: "clock_settime", 228: "clock_gettime",
    229: "clock_getres", 230: "clock_nanosleep", 231: "exit_group",
    232: "epoll_wait", 233: "epoll_ctl", 234: "tgkill", 235: "utimes",
    236: "vserver", 237: "mbind", 238: "set_mempolicy", 239: "get_mempolicy",
    240: "mq_open", 241: "mq_unlink", 242: "mq_timedsend", 243: "mq_timedreceive",
    244: "mq_notify", 245: "mq_getsetattr", 246: "kexec_load", 247: "waitid",
    248: "add_key", 249: "request_key", 250: "keyctl", 251: "ioprio_set",
    252: "ioprio_get", 253: "inotify_init", 254: "inotify_add_watch",
    255: "inotify_rm_watch", 256: "migrate_pages", 257: "openat",
    258: "mkdirat", 259: "mknodat", 260: "fchownat", 261: "futimesat",
    262: "newfstatat", 263: "unlinkat", 264: "renameat", 265: "linkat",
    266: "symlinkat", 267: "readlinkat", 268: "fchmodat", 269: "faccessat",
    270: "pselect6", 271: "ppoll", 272: "unshare", 273: "set_robust_list",
    274: "get_robust_list", 275: "splice", 276: "tee", 277: "sync_file_range",
    278: "vmsplice", 279: "move_pages", 280: "utimensat", 281: "epoll_pwait",
    282: "signalfd", 283: "timerfd_create", 284: "eventfd", 285: "fallocate",
    286: "timerfd_settime", 287: "timerfd_gettime", 288: "accept4",
    289: "signalfd4", 290: "eventfd2", 291: "epoll_create1", 292: "dup3",
    293: "pipe2", 294: "inotify_init1", 295: "preadv", 296: "pwritev",
    297: "rt_tgsigqueueinfo", 298: "perf_event_open", 299: "recvmmsg",
    300: "fanotify_init", 301: "fanotify_mark", 302: "prlimit64",
    303: "name_to_handle_at", 304: "open_by_handle_at", 305: "clock_adjtime",
    306: "syncfs", 307: "sendmmsg", 308: "setns", 309: "getcpu",
    310: "process_vm_readv", 311: "process_vm_writev", 312: "kcmp",
    313: "finit_module", 314: "sched_setattr", 315: "sched_getattr",
    316: "renameat2", 317: "seccomp", 318: "getrandom", 319: "memfd_create",
    320: "kexec_file_load", 321: "bpf", 322: "execveat", 323: "userfaultfd",
    324: "membarrier", 325: "mlock2", 326: "copy_file_range", 327: "preadv2",
    328: "pwritev2", 329: "pkey_mprotect", 330: "pkey_alloc", 331: "pkey_free",
    332: "statx"
}

def resolve_syscall_name(syscall_id: int) -> str:
    """
    Safely resolves a numeric system call identifier to its canonical x86_64 name.
    If unknown or out of range, returns 'unknown(<id>)' without throwing exceptions.
    Never substitutes an arbitrary or incorrect syscall name.
    """
    try:
        sc_id = int(syscall_id)
        return X86_64_SYSCALL_MAP.get(sc_id, f"unknown({sc_id})")
    except (ValueError, TypeError):
        return f"invalid({syscall_id})"


# ==============================================================================
# 2. Syscall Functional Categories (x86_64 Numeric IDs)
# ==============================================================================

# Process Execution
SYSCALLS_EXEC: Set[int] = {59, 322}  # execve, execveat

# Process Tracing & Debugging
SYSCALLS_PTRACE: Set[int] = {101}  # ptrace

# Identity, Privilege & Capability Modification
SYSCALLS_PRIVILEGE: Set[int] = {
    105, 106, 113, 114, 117, 119, 122, 123, 126  # setuid, setgid, setreuid, setregid, setresuid, setresgid, setfsuid, setfsgid, capset
}

# Namespace & Root Manipulation
SYSCALLS_NAMESPACE_ROOT: Set[int] = {
    155, 161, 272, 308  # pivot_root, chroot, unshare, setns
}

# Kernel Module Insertion & Kernel Modification
SYSCALLS_KERNEL_MOD: Set[int] = {
    174, 175, 176, 246, 313, 320, 321  # create_module, init_module, delete_module, kexec_load, finit_module, kexec_file_load, bpf
}

# Network Socket Creation & Communication Operations
SYSCALLS_NETWORK: Set[int] = {
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 53, 288  # socket, connect, accept, sendto, recvfrom, sendmsg, recvmsg, shutdown, bind, listen, socketpair, accept4
}

# Network Connection Establishment Specifically (Connect/Accept)
SYSCALLS_NET_CONNECT: Set[int] = {42, 43, 288}  # connect, accept, accept4

# Process Manipulation & Signaling
SYSCALLS_PROCESS_MANIP: Set[int] = {62, 200, 234}  # kill, tkill, tgkill

# File Permission & Attribute Modification
SYSCALLS_PERMISSION: Set[int] = {90, 91, 268}  # chmod, fchmod, fchmodat

# Memory Permission & Allocation
SYSCALLS_MEM_PROTECT: Set[int] = {9, 10, 25, 329}  # mmap, mprotect, mremap, pkey_mprotect

# Filesystem Mutation (Creation/Deletion/Renaming)
SYSCALLS_FS_MUTATION: Set[int] = {
    82, 83, 84, 85, 86, 87, 88, 257, 258, 259, 263, 264, 265, 266, 316  # rename, mkdir, rmdir, creat, link, unlink, symlink, openat, mkdirat, mknodat, unlinkat, renameat, linkat, symlinkat, renameat2
}

# Routine I/O, Polling, Time & Synchronization (Benign baseline operations)
SYSCALLS_ROUTINE_IO: Set[int] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
    23, 24, 32, 33, 34, 35, 36, 37, 38, 39, 72, 73, 74, 75, 78, 79, 96,
    97, 98, 99, 100, 102, 104, 107, 108, 110, 111, 201, 202, 213, 217,
    218, 221, 228, 229, 230, 231, 232, 233, 262, 270, 271, 281, 291, 292,
    293, 318, 332
}


# ==============================================================================
# 3. Severity Classification Result Structure
# ==============================================================================

class SeverityClassification:
    """Encapsulates the deterministic outcome of alert severity classification."""
    __slots__ = (
        "severity",
        "rule_id",
        "rule_description",
        "relevant_syscalls",
        "reason",
        "rule_version"
    )

    def __init__(
        self,
        severity: str,
        rule_id: str,
        rule_description: str,
        relevant_syscalls: List[str],
        reason: str,
        rule_version: str = RULE_ENGINE_VERSION
    ):
        self.severity = severity
        self.rule_id = rule_id
        self.rule_description = rule_description
        self.relevant_syscalls = relevant_syscalls
        self.reason = reason
        self.rule_version = rule_version

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity,
            "severity_rule": self.rule_id,
            "rule_description": self.rule_description,
            "relevant_syscalls": self.relevant_syscalls,
            "severity_reason": self.reason,
            "severity_rule_version": self.rule_version
        }

    def __repr__(self) -> str:
        return f"<SeverityClassification {self.severity} [{self.rule_id}]: {self.reason}>"


# ==============================================================================
# 4. Explainable Rule Registry & Classification Engine
# ==============================================================================

def classify_severity(
    s1: int,
    s2: int,
    s3: int,
    anomaly_score: float,
    process_name: Optional[str] = None
) -> SeverityClassification:
    """
    Evaluates an anomalous syscall 3-gram sequence and deterministically classifies
    its security severity level based on explicit, explainable rules.

    Precedence Order:
      1. CRITICAL
      2. HIGH
      3. MEDIUM
      4. LOW

    Notice:
    - This function does NOT alter anomaly detection scores or the 0.80 threshold.
    - It evaluates security priority to assist security analysts in triage.
    - Does NOT claim that an alert proves malicious execution.
    """
    syscall_ids = [int(s1), int(s2), int(s3)]
    syscall_names = [resolve_syscall_name(sc) for sc in syscall_ids]
    seq_set = set(syscall_ids)
    score = float(anomaly_score)
    clean_proc = str(process_name or "").strip().lower()

    # --------------------------------------------------------------------------
    # PRECEDENCE 1: CRITICAL RULES
    # Strongly corroborated security-sensitive behavior using collected context.
    # --------------------------------------------------------------------------

    # Rule 1.1: Privilege Escalation or Capability Modification
    priv_matches = [name for sc, name in zip(syscall_ids, syscall_names) if sc in SYSCALLS_PRIVILEGE]
    if priv_matches:
        joined = ", ".join(dict.fromkeys(priv_matches))
        return SeverityClassification(
            severity="CRITICAL",
            rule_id="CRITICAL_PRIVILEGE_OR_CAPABILITY",
            rule_description="Anomalous sequence contains credential, user identity, or capability modification primitives.",
            relevant_syscalls=priv_matches,
            reason=f"Anomalous sequence contains credential/privilege alteration syscall ({joined}). This constitutes sensitive administrative transition and warrants immediate security review, but does not independently prove an exploit."
        )

    # Rule 1.2: Root Pivoting / Namespace Escape
    ns_matches = [name for sc, name in zip(syscall_ids, syscall_names) if sc in SYSCALLS_NAMESPACE_ROOT]
    if ns_matches:
        joined = ", ".join(dict.fromkeys(ns_matches))
        return SeverityClassification(
            severity="CRITICAL",
            rule_id="CRITICAL_NAMESPACE_OR_ROOT_PIVOT",
            rule_description="Anomalous sequence contains filesystem root pivoting or namespace isolation alterations.",
            relevant_syscalls=ns_matches,
            reason=f"Anomalous sequence contains namespace or root pivoting operation ({joined}). Such transitions modify container/jail boundaries and require immediate operational review."
        )

    # Rule 1.3: Kernel Module Insertion / eBPF / Kexec Manipulation
    kmod_matches = [name for sc, name in zip(syscall_ids, syscall_names) if sc in SYSCALLS_KERNEL_MOD]
    if kmod_matches:
        joined = ", ".join(dict.fromkeys(kmod_matches))
        return SeverityClassification(
            severity="CRITICAL",
            rule_id="CRITICAL_KERNEL_MODIFICATION",
            rule_description="Anomalous sequence invokes kernel module, kexec, or kernel BPF modification primitives.",
            relevant_syscalls=kmod_matches,
            reason=f"Anomalous sequence invokes kernel-level modification primitives ({joined}). Kernel tampering or module loading represents high-impact system state alteration."
        )

    # Rule 1.4: Process Execution Combined with Network Connection within 3-Gram
    has_exec = any(sc in SYSCALLS_EXEC for sc in syscall_ids)
    has_net_conn = any(sc in SYSCALLS_NET_CONNECT for sc in syscall_ids)
    if has_exec and has_net_conn:
        relevant = [name for sc, name in zip(syscall_ids, syscall_names) if sc in SYSCALLS_EXEC or sc in SYSCALLS_NET_CONNECT]
        return SeverityClassification(
            severity="CRITICAL",
            rule_id="CRITICAL_EXEC_WITH_NETWORK",
            rule_description="Anomalous sequence combines process execution with network connection primitives within the same 3-gram window.",
            relevant_syscalls=relevant,
            reason="Anomalous sequence couples process spawning with active network connection establishment. This correlated behavior frequently indicates remote execution, shell delivery, or exfiltration triage priority."
        )

    # Rule 1.5: Process Tracing Combined with Memory Alteration
    has_ptrace = any(sc in SYSCALLS_PTRACE for sc in syscall_ids)
    has_mem_prot = any(sc in SYSCALLS_MEM_PROTECT for sc in syscall_ids)
    if has_ptrace and has_mem_prot:
        relevant = [name for sc, name in zip(syscall_ids, syscall_names) if sc in SYSCALLS_PTRACE or sc in SYSCALLS_MEM_PROTECT]
        return SeverityClassification(
            severity="CRITICAL",
            rule_id="CRITICAL_TRACING_WITH_MEMORY_MOD",
            rule_description="Anomalous sequence combines process debugging/tracing with memory protection modifications.",
            relevant_syscalls=relevant,
            reason="Anomalous sequence combines ptrace with memory protection modification. Such patterns correlate with code injection or runtime hooking techniques and warrant priority inspection."
        )

    # --------------------------------------------------------------------------
    # PRECEDENCE 2: HIGH RULES
    # Anomalous sequences containing security-sensitive syscall categories.
    # --------------------------------------------------------------------------

    # Rule 2.1: Process Execution
    if has_exec:
        exec_matches = [name for sc, name in zip(syscall_ids, syscall_names) if sc in SYSCALLS_EXEC]
        joined = ", ".join(dict.fromkeys(exec_matches))
        return SeverityClassification(
            severity="HIGH",
            rule_id="HIGH_PROCESS_EXECUTION",
            rule_description="Anomalous sequence contains process execution syscalls.",
            relevant_syscalls=exec_matches,
            reason=f"The anomalous sequence contains a process execution syscall ({joined}). This is security-sensitive behavior and warrants review, but does not independently prove malicious execution."
        )

    # Rule 2.2: Process Tracing
    if has_ptrace:
        return SeverityClassification(
            severity="HIGH",
            rule_id="HIGH_PROCESS_TRACING",
            rule_description="Anomalous sequence contains ptrace debugging or process inspection.",
            relevant_syscalls=["ptrace"],
            reason="The anomalous sequence contains ptrace. Process tracing can inspect and alter thread state, warranting elevated triage priority."
        )

    # Rule 2.3: Network Activity
    net_matches = [name for sc, name in zip(syscall_ids, syscall_names) if sc in SYSCALLS_NETWORK]
    if net_matches:
        joined = ", ".join(dict.fromkeys(net_matches))
        return SeverityClassification(
            severity="HIGH",
            rule_id="HIGH_NETWORK_ACTIVITY",
            rule_description="Anomalous sequence contains network socket creation or communication operations.",
            relevant_syscalls=net_matches,
            reason=f"The anomalous sequence contains network socket operations ({joined}). Deviations in network communications are security-sensitive and warrant review."
        )

    # Rule 2.4: Process Manipulation / Signaling
    manip_matches = [name for sc, name in zip(syscall_ids, syscall_names) if sc in SYSCALLS_PROCESS_MANIP]
    if manip_matches:
        joined = ", ".join(dict.fromkeys(manip_matches))
        return SeverityClassification(
            severity="HIGH",
            rule_id="HIGH_PROCESS_MANIPULATION",
            rule_description="Anomalous sequence contains process signaling or termination primitives.",
            relevant_syscalls=manip_matches,
            reason=f"The anomalous sequence contains process signaling primitives ({joined}). Unexpected process termination or signal delivery warrants investigation."
        )

    # Rule 2.5: Permission Changes
    perm_matches = [name for sc, name in zip(syscall_ids, syscall_names) if sc in SYSCALLS_PERMISSION]
    if perm_matches:
        joined = ", ".join(dict.fromkeys(perm_matches))
        return SeverityClassification(
            severity="HIGH",
            rule_id="HIGH_PERMISSION_CHANGE",
            rule_description="Anomalous sequence modifies file permissions.",
            relevant_syscalls=perm_matches,
            reason=f"The anomalous sequence contains file permission alterations ({joined}). Permission modifications can expose assets or alter access control."
        )

    # --------------------------------------------------------------------------
    # PRECEDENCE 3: LOW RULES (Check before default MEDIUM)
    # Low-priority suspicious behavior: Marginal anomaly score consisting purely
    # of routine I/O, polling, or time/synchronization primitives.
    # --------------------------------------------------------------------------
    is_purely_routine = all(sc in SYSCALLS_ROUTINE_IO for sc in syscall_ids)
    if is_purely_routine and score < 0.90:
        return SeverityClassification(
            severity="LOW",
            rule_id="LOW_ROUTINE_IO_DEVIATION",
            rule_description="Marginal statistical anomaly consisting entirely of routine I/O, polling, or time operations.",
            relevant_syscalls=syscall_names,
            reason="Anomalous sequence consists exclusively of benign routine I/O, polling, or synchronization primitives (score near threshold). Warrants low triage priority."
        )

    # --------------------------------------------------------------------------
    # PRECEDENCE 4: MEDIUM RULES
    # Suspicious syscall sequences without a verified high-risk indicator.
    # --------------------------------------------------------------------------

    # Rule 4.1: Filesystem Mutation (Creation/Deletion/Renaming)
    fs_matches = [name for sc, name in zip(syscall_ids, syscall_names) if sc in SYSCALLS_FS_MUTATION]
    if fs_matches:
        joined = ", ".join(dict.fromkeys(fs_matches))
        return SeverityClassification(
            severity="MEDIUM",
            rule_id="MEDIUM_FILESYSTEM_MUTATION",
            rule_description="Suspicious sequence contains filesystem creation, deletion, or renaming operations.",
            relevant_syscalls=fs_matches,
            reason=f"The anomalous sequence involves filesystem mutation ({joined}) without process execution or network activity. Warrants standard investigation."
        )

    # Rule 4.2: Unseen 3-Gram Sequence (Score = 1.0)
    if score >= 1.0:
        return SeverityClassification(
            severity="MEDIUM",
            rule_id="MEDIUM_UNSEEN_SEQUENCE",
            rule_description="Unseen 3-gram sequence never observed in normal baseline training.",
            relevant_syscalls=syscall_names,
            reason="Syscall sequence was never observed during normal baseline training (score 1.0000). While novel, it contains no explicit high-risk execution or network primitives."
        )

    # Rule 4.3: Default Medium for General Statistical Deviations
    return SeverityClassification(
        severity="MEDIUM",
        rule_id="MEDIUM_STATISTICAL_DEVIATION",
        rule_description="Statistically deviant syscall sequence above anomaly threshold.",
        relevant_syscalls=syscall_names,
        reason=f"Sequence exceeded the anomaly threshold (score {score:.4f} >= 0.80) without matching specific high-risk security rule categories."
    )
