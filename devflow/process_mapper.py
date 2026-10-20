import os
import time


class ProcessMapper:
    def __init__(self, cache_ttl=2.0):
        # Cache {(port): ("process_name (PID)", timestamp)} to avoid excessive /proc scans
        self.port_cache = {}
        self.inode_to_proc = {}
        self.last_scan_time = 0
        self.cache_ttl = cache_ttl

    def resolve(self, src_port, dst_port):
        """
        Attempts to map either src_port or dst_port to a local Linux process and PID.
        Returns a formatted string like 'python3 (PID: 4821)' or 'Unknown'.
        """
        now = time.time()

        # Check fast cache first
        for port in (src_port, dst_port):
            if port in self.port_cache:
                proc_str, ts = self.port_cache[port]
                if now - ts < self.cache_ttl:
                    return proc_str

        # Parse /proc/net/tcp and /proc/net/tcp6 to find socket inodes for active ports
        target_inodes = {}
        for proc_net_file in ("/proc/net/tcp", "/proc/net/tcp6"):
            if not os.path.exists(proc_net_file):
                continue
            try:
                with open(proc_net_file, "r") as f:
                    lines = f.readlines()[1:]  # Skip header row
                for line in lines:
                    parts = line.split()
                    if len(parts) < 10:
                        continue
                    # local_address is hex_ip:hex_port
                    local_addr = parts[1]
                    inode = parts[9]
                    if inode == "0":
                        continue
                    port_hex = local_addr.split(":")[1]
                    local_port = int(port_hex, 16)
                    if local_port in (src_port, dst_port):
                        target_inodes[local_port] = inode
            except (OSError, ValueError):
                continue

        if not target_inodes:
            return "system/ephemeral"

        # Check if we already mapped this inode recently, otherwise refresh /proc/<pid>/fd
        for port, inode in target_inodes.items():
            if inode not in self.inode_to_proc or (now - self.last_scan_time > self.cache_ttl):
                self._refresh_inode_map()
                break

        # Prefer the client/initiating port first, then fallback to server port
        for port in (src_port, dst_port):
            inode = target_inodes.get(port)
            if inode and inode in self.inode_to_proc:
                proc_str = self.inode_to_proc[inode]
                self.port_cache[port] = (proc_str, now)
                return proc_str

        return "system/ephemeral"

    def _refresh_inode_map(self):
        """Scans /proc/<pid>/fd/ symlinks to map socket:[inode] -> Process Name & PID."""
        self.last_scan_time = time.time()
        new_map = {}

        try:
            pids = [d for d in os.listdir("/proc") if d.isdigit()]
        except OSError:
            return

        for pid in pids:
            fd_dir = f"/proc/{pid}/fd"
            try:
                fds = os.listdir(fd_dir)
            except (PermissionError, FileNotFoundError, ProcessLookupError):
                continue

            comm_name = None
            for fd in fds:
                try:
                    link = os.readlink(f"{fd_dir}/{fd}")
                    if link.startswith("socket:[") and link.endswith("]"):
                        inode = link[8:-1]
                        if comm_name is None:
                            with open(f"/proc/{pid}/comm", "r") as cf:
                                comm_name = cf.read().strip()
                        new_map[inode] = f"{comm_name} (PID:{pid})"
                except (OSError, PermissionError):
                    continue

        self.inode_to_proc = new_map