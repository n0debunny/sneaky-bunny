import os

def get_processes():
    processes = []
    for pid in os.listdir('/proc'):
        if pid.isdigit():
            processes.append(pid)
    return processes

def check_path(pid):
    try:
        exe_path = os.readlink(f'/proc/{pid}/exe')
        suspicious_paths = ['/tmp', '/dev/shm', '/var/tmp']
        for path in suspicious_paths:
            if exe_path.startswith(path):
                return True, exe_path
        return False, exe_path
    except:
        return False, ''

def check_memory(pid):
    try:
        with open(f'/proc/{pid}/maps', 'r') as maps:
            for line in maps:
                parts = line.split()
                if len(parts) >= 2:
                    permissions = parts[1]
                    if 'rwx' in permissions:
                        return True
        return False
    except:
        return False

def run_scan():
    alerts = []
    pids = get_processes()
    for pid in pids:
        suspicious_path, exe_path = check_path(pid)
        rwx_memory = check_memory(pid)
        if suspicious_path or rwx_memory:
            alerts.append({
                'pid': pid,
                'path': exe_path if exe_path else 'unknown',
                'rwx': rwx_memory,
                'path_alert': suspicious_path
            })
    return alerts
