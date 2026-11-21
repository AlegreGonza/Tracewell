"""psutil FALSO para probar backend/domain/system sin tocar el sistema real.

Cualquier función que MODIFIQUE el sistema (kill, terminate, suspend, resume, nice, ionice, cpu_affinity, send_signal...)
o cualquier otra que el código no debería llamar hace fallar el test con AssertionError.
"""
import contextlib
import socket
from types import SimpleNamespace

FORBIDDEN = ("kill", "terminate", "suspend", "resume", "nice", "ionice", "cpu_affinity", "send_signal", "rlimit", "wait", "environ")


class AccessDenied(Exception):
    pass


class NoSuchProcess(Exception):
    pass


def addr(ip, port):
    return SimpleNamespace(ip=ip, port=port)


def conn(laddr=None, raddr=None, status="ESTABLISHED", pid=None, type=socket.SOCK_STREAM):
    return SimpleNamespace(fd=-1, family=socket.AF_INET, type=type, laddr=laddr, raddr=raddr, status=status, pid=pid)


class FakeProcess:
    """Un proceso. `deny` = nombres de lectura que fallan con AccessDenied; `gone` = los que fallan con NoSuchProcess."""

    def __init__(self, pid, name="prog.exe", exe="/usr/bin/prog", cmdline=("prog", "-x"), ppid=1, username="ana", status="running",
                 create_time=1_700_000_000.0, rss=1_000_000, vms=2_000_000, threads=4, cpu=0.0, cwd="/home/ana",
                 io=(10, 20), children=(), open_files=(), maps=(), conns=(), deny=(), gone=(), parent=None, no_name=False):
        self.pid = pid
        self._v = dict(name=None if no_name else name, exe=exe, cmdline=list(cmdline), ppid=ppid, username=username, status=status,
                       create_time=create_time, num_threads=threads, cwd=cwd)
        self._rss, self._vms, self._cpu, self._io = rss, vms, cpu, io
        self._children, self._open, self._maps, self._conns = list(children), list(open_files), list(maps), list(conns)
        self._deny, self._gone, self._parent = set(deny), set(gone), parent
        self.calls = []

    def _read(self, key):
        self.calls.append(key)
        if key in self._deny:
            raise AccessDenied(key)
        if key in self._gone:
            raise NoSuchProcess(key)

    @property
    def info(self):
        return {"pid": self.pid, "name": self._v["name"]}

    @contextlib.contextmanager
    def oneshot(self):
        self._read("oneshot")
        yield

    def _simple(key):
        def method(self):
            self._read(key)
            return self._v[key]
        return method

    name = _simple("name")
    exe = _simple("exe")
    cmdline = _simple("cmdline")
    ppid = _simple("ppid")
    username = _simple("username")
    status = _simple("status")
    create_time = _simple("create_time")
    num_threads = _simple("num_threads")
    cwd = _simple("cwd")

    def cpu_percent(self, interval=None):
        self._read("cpu_percent")
        return self._cpu

    def memory_info(self):
        self._read("memory_info")
        return SimpleNamespace(rss=self._rss, vms=self._vms)

    def io_counters(self):
        self._read("io_counters")
        return None if self._io is None else SimpleNamespace(read_bytes=self._io[0], write_bytes=self._io[1])

    def parent(self):
        self._read("parent")
        return self._parent

    def children(self, recursive=False):
        self._read("children")
        return self._children

    def open_files(self):
        self._read("open_files")
        return [SimpleNamespace(path=p) for p in self._open]

    def memory_maps(self, grouped=True):
        self._read("memory_maps")
        return [SimpleNamespace(path=p) for p in self._maps]

    def net_connections(self, kind="inet"):
        self._read("net_connections")
        return self._conns

    def __getattr__(self, name):
        if name in FORBIDDEN or not name.startswith("_"):
            raise AssertionError(f"el código llamó a Process.{name}(): no está permitido o no se esperaba")
        raise AttributeError(name)


class FakeService:
    def __init__(self, **info):
        self._info = info
        self.fail = info.pop("_fail", False)

    def as_dict(self):
        if self.fail:
            raise AccessDenied("service")
        return dict(self._info)


class FakePsutil:
    AccessDenied = AccessDenied
    NoSuchProcess = NoSuchProcess

    def __init__(self, procs=(), connections=(), services=(), cpu=12.5, ncpu=4, physical=2, pids=None, boot=1_000.0,
                 mem=(8_000, 3_000, 62.5), swap=(1_000, 100, 10.0), battery=(80.0, True), net_io=(111, 222), disks=None,
                 deny=(), conn_error=False):
        self.procs = list(procs)
        self.connections = list(connections)
        self._services = list(services)
        self._cpu, self._ncpu, self._physical, self._boot = cpu, ncpu, physical, boot
        self._pids, self._mem, self._swap, self._battery, self._net_io = pids, mem, swap, battery, net_io
        self._disks = disks if disks is not None else [("C:\\", "NTFS", 1000, 400, 40.0), ("D:\\", "exFAT", None, None, None)]
        self._deny, self._conn_error = set(deny), conn_error

    def _check(self, key):
        if key in self._deny:
            raise AccessDenied(key)

    def process_iter(self, attrs=None):
        self._check("process_iter")
        return iter(self.procs)

    def Process(self, pid):
        for p in self.procs:
            if p.pid == pid:
                return p
        raise NoSuchProcess(pid)

    def net_connections(self, kind="inet"):
        if self._conn_error:
            raise AccessDenied("net_connections")
        return list(self.connections)

    def virtual_memory(self):
        total, avail, pct = self._mem
        return SimpleNamespace(total=total, available=avail, percent=pct)

    def swap_memory(self):
        self._check("swap_memory")
        return None if self._swap is None else SimpleNamespace(total=self._swap[0], used=self._swap[1], percent=self._swap[2])

    def sensors_battery(self):
        self._check("sensors_battery")
        return None if self._battery is None else SimpleNamespace(percent=self._battery[0], power_plugged=self._battery[1])

    def net_io_counters(self):
        self._check("net_io_counters")
        return None if self._net_io is None else SimpleNamespace(bytes_sent=self._net_io[0], bytes_recv=self._net_io[1])

    def boot_time(self):
        self._check("boot_time")
        return self._boot

    def disk_partitions(self, all=False):
        self._check("disk_partitions")
        return [SimpleNamespace(mountpoint=m, fstype=f) for m, f, *_ in self._disks]

    def disk_usage(self, mount):
        for m, _f, total, used, pct in self._disks:
            if m == mount:
                if total is None:
                    raise AccessDenied(mount)
                return SimpleNamespace(total=total, used=used, percent=pct)
        raise AccessDenied(mount)

    def cpu_percent(self, interval=None):
        return self._cpu

    def cpu_count(self, logical=True):
        if logical:
            return self._ncpu
        self._check("cpu_physical")
        return self._physical

    def pids(self):
        return list(self._pids) if self._pids is not None else [p.pid for p in self.procs]

    def win_service_iter(self):
        self._check("win_service_iter")
        return iter(self._services)

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        raise AssertionError(f"el código llamó a psutil.{name}: no está permitido o no se esperaba")


def patch_psutil(monkeypatch, fake):
    """Hace que TODOS los módulos de backend.domain.system usen `fake` en lugar de psutil."""
    from backend.domain.system import autostart, net, overview, procs
    for mod in (autostart, net, overview, procs):
        monkeypatch.setattr(mod, "psutil_or_raise", lambda fake=fake: fake)
    return fake
