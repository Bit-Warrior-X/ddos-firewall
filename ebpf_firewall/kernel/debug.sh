# 1. Check systemd logs for crash reasons (most recent 100 lines)
journalctl -u ebpf-firewall -n 100 --no-pager

# 2. Check if it's being killed by OOM killer
dmesg | grep -i -E "oom|killed|ebpf_firewall" | tail -20

# 3. Check service status and recent restart history
systemctl status ebpf-firewall

# 4. Check how many times it restarted recently
journalctl -u ebpf-firewall --since "1 hour ago" | grep -c "Started\|Stopped\|Main process exited"

# 5. Check for core dumps
coredumpctl list 2>/dev/null | tail -10

# 6. Check your firewall's own log file
tail -200 /var/firewall.log | grep -E "ERROR|CRITIC|signal|Segmentation|SIGKILL|SIGTERM"

# 7. Check kernel ring buffer for BPF-related errors
dmesg | grep -i -E "bpf|xdp|memlock|ENOMEM" | tail -20