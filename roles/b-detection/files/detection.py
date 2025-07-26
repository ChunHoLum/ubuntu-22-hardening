#!/usr/bin/env python3

import os
import subprocess
import time
import datetime
import json
import socket
import re
import psutil

LOG_FILE = "/var/log/custom-security-events-detection.json"
POLL_INTERVAL = 8 
HOSTNAME = socket.gethostname()

AUTH_FILE_MODIFIER_WHITELIST = [
    "/usr/bin/passwd", "/usr/sbin/useradd", "/usr/sbin/usermod",
    "/usr/sbin/groupadd", "/usr/sbin/groupmod", "/usr/sbin/chsh", "/usr/bin/chfn"
]

AUDIT_KEYS_TO_WATCH = {
    "auth_file_change": "AUTH_FILE_TAMPERING",
    "cron_file_change": "CRON_JOB_MODIFIED"
}

def generate_alert_base(event_type, summary):
    return {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "hostname": HOSTNAME, "event_type": event_type, "summary": summary, "details": {}
    }

def log_alert(alert_data):
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(json.dumps(alert_data) + '\n')
    except Exception as e:
        print(f"ERROR: Could not write to log file {LOG_FILE}: {e}")

def alert_in_console(alert_data):
    print("\n" + "------")
    print(f"Timestamp: {alert_data['timestamp']}")
    print(f"Event:     {alert_data['event_type']}")
    print(f"Summary:   {alert_data['summary']}")
    print("Details:")
    for key, value in alert_data['details'].items():
        print(f"    {key}: {value}")
    print("------" + "\n")

def process_alert(alert_data):
    log_alert(alert_data)
    alert_in_console(alert_data)

def parse_ausearch_event(event_blob):
    event_data = {'paths': []}
    for line in event_blob.strip().split('\n'):
        type_match = re.match(r'type=(\w+)', line)
        if not type_match: continue
        
        record_type = type_match.group(1)
        
        if record_type == 'SYSCALL':
            exe_match = re.search(r' exe=([^ ]+)', line)
            key_match = re.search(r' key=([^ ]+)', line)
            if exe_match: event_data['exe'] = exe_match.group(1)
            if key_match: event_data['key'] = key_match.group(1)
        
        elif record_type == 'PATH':
            nametype_match = re.search(r' nametype=(\w+)', line)
            if nametype_match and nametype_match.group(1) in ('CREATE', 'DELETE', 'MODIFY', 'NORMAL'):
                name_match = re.search(r' name=([^ ]+)', line)
                if name_match: event_data['paths'].append(name_match.group(1))
    print(f"Parsed event data: {event_data}")
    return event_data

def check_file_modifications(last_check_time):
    start_str_time = last_check_time.strftime('%H:%M:%S')

    for key in AUDIT_KEYS_TO_WATCH.keys():
        try:
            cmd = ['ausearch', '-k', key, '--start', start_str_time, '--interpret']  
            output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)

            for event_blob in output.strip().split('----'):
                if not event_blob.strip():
                    continue

                event_data = parse_ausearch_event(event_blob)

                audit_key = event_data.get('key')
                modifier_exe = event_data.get('exe')
                file_paths = event_data.get('paths', [])

                if not (audit_key and modifier_exe and file_paths):
                    continue

                if audit_key in AUDIT_KEYS_TO_WATCH:
                    event_type = AUDIT_KEYS_TO_WATCH[audit_key]
                    
                    for file_path in file_paths:
                        if event_type == AUDIT_KEYS_TO_WATCH['auth_file_change']:
                            if modifier_exe not in AUTH_FILE_MODIFIER_WHITELIST:
                                alert = generate_alert_base(event_type, "Authentication file modified by a non-standard program.")
                                alert['details'] = {"file_path": file_path, "modifying_process": modifier_exe}
                                process_alert(alert)
                        elif event_type == AUDIT_KEYS_TO_WATCH['cron_file_change']: # For cron jobs, etc.
                            alert = generate_alert_base(event_type, "A system or user cron job was created or modified.")
                            alert['details'] = {"file_path": file_path, "modifying_process": modifier_exe}
                            process_alert(alert)

        except (subprocess.CalledProcessError, FileNotFoundError):
            continue

    # Return the time of this check, to be used as the 'start_time' for the next one.
    return datetime.datetime.now()

def get_initial_journal_cursor(identifier):
    try:
        cmd = ['journalctl', identifier, '-n', '1', '-o', 'json']
        output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
        return json.loads(output).get('__CURSOR') if output else None
    except Exception: return None

def check_su_logs(last_cursor):
    cmd = ['journalctl', '_COMM=su', '--after-cursor', last_cursor, '-o', 'json', '--no-pager'] if last_cursor else ['journalctl', '_COMM=su', '-o', 'json', '--no-pager']
    
    try:
        output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
        new_cursor = last_cursor

        for line in output.strip().split('\n'):
            if not line: continue
            log_entry = json.loads(line)
            new_cursor = log_entry.get('__CURSOR')
            
            message = log_entry.get('MESSAGE', '')
            if "session opened for user root" in message:
                original_user = "unknown"
                match = re.search(r'by\s(.*?)\(', message)
                if match:
                    original_user = match.group(1)

                alert = generate_alert_base(
                    "ROOT_LOGIN_DETECTED",
                    "A user switched to the root account using 'su'."
                )
                alert['details'] = {
                    "original_user": original_user,
                    "log_entry": message.strip()
                }
                process_alert(alert)
                
        return new_cursor
    except (subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError):
        return last_cursor
    
def check_sudo_logs(last_cursor):
    cmd = ['journalctl', '_COMM=sudo', '--after-cursor', last_cursor, '-o', 'json'] if last_cursor else ['journalctl', '_COMM=sudo', '-o', 'json']
    try:
        output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
        new_cursor = last_cursor

        for line in output.strip().split('\n'):
            if not line: continue
            log_entry = json.loads(line)
            new_cursor = log_entry.get('__CURSOR')
            message = log_entry.get('MESSAGE', '')
            if "authentication failure" in message or "NOT in sudoers" in message or "unknown user" in message:
                alert = generate_alert_base("SUDO_FAILURE", "A user failed to gain sudo privileges.")
                alert['details'] = {"reason": message, "user": log_entry.get('SUDO_USER', 'N/A')}
                process_alert(alert)
            command = log_entry.get('SUDO_COMMAND', '')
            ## I added typical privilege escalation patterns to the command check.
            ## CVE-2019-14287  https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/linux/privilege_escalation_sudo_cve_2019_14287
            if command and ("-u#-1" in command or "-u#4294967295" in command):
                alert = generate_alert_base("SUDO_PRIVILEGE_ESCALATION", "Potential sudo privilege escalation attack detected.")
                alert['details'] = {"user": log_entry.get('SUDO_USER'), "full_command": command}
                process_alert(alert)
        return new_cursor
    except Exception: return last_cursor

def check_reverse_shells():
    for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
        if proc.info['name'] in ["bash", "sh", "nc", "python", "perl", "zsh", "ksh"]:
            try:
                # This simple reverse shell check if process redirects the standard input and output to a socket.
                if os.readlink(f"/proc/{proc.pid}/fd/0") == os.readlink(f"/proc/{proc.pid}/fd/1") and os.readlink(f"/proc/{proc.pid}/fd/0").startswith('socket:'):
                    alert = generate_alert_base("REVERSE_SHELL_DETECTED", f"Potential reverse shell detected via process '{proc.info['name']}'.")
                    alert['details']['process'] = proc.info
                    process_alert(alert)
                    break
            except (FileNotFoundError, psutil.NoSuchProcess):
                continue

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("ERROR: This script must be run as root.")
        exit(1)
        
    print("Monitoring started, all alerts will be logged to:", LOG_FILE)
    # cursor for sudo and su log events
    sudo_cursor = get_initial_journal_cursor('_COMM=sudo')
    su_cursor = get_initial_journal_cursor('_COMM=su')
    # Initialize the audit check time. We subtract a second to avoid missing
    # any event that happens between this line and the first check.
    last_audit_check_time = datetime.datetime.now() - datetime.timedelta(seconds=1)

    print("Monitoring has begun. Press Ctrl+C to stop. ---\n")

    try:
        while True:
            # Event 1 & 2 auth and cron file modifications
            last_audit_check_time = check_file_modifications(last_audit_check_time)
            # Event 3 sudo logs 
            new_sudo_cursor = check_sudo_logs(sudo_cursor)
            if new_sudo_cursor: sudo_cursor = new_sudo_cursor
            # Event 4 su logs 
            new_su_cursor = check_su_logs(su_cursor)
            if new_su_cursor: su_cursor = new_su_cursor
            # Event 5 reverse shells            
            check_reverse_shells()
            # Sleep for the defined interval before the next check.
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")