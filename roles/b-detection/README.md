# B. Script for Detecting Suspicious Admin Activity

This role is aimed to setup and install a script for detecting suspicious admin activity.

## How to install the script

You can install the script via the core provisioner playbook [readme.md](/README.md)

```sh
ansible-playbook provisioner.yml --tags b
```

The provisioner will install all the dependices and install the script to `/opt/detection.py`

Dependices used:

-   python3/pip
-   psutil
-   journalctl
-   auditd/ausearch

## How to run the script

```sh
sudo python3 /opt/detection.py
# or run in background
sudo python3 /opt/detection.py &
# and check the log in
tail -f /var/log/custom-security-events-detection.json
```

The script will print the detected event in the console also logged to `/var/log/custom-security-events-detection.json` in json format. The monitor loop will have a `8` second of interval gap.

## Chosen Security Events

I have selected 4 security events to monitor, will explain why and how in the following.

-   Critical File Modification - auth related files
-   Cron Job Creation or Modification
-   Failed Sudo Attempts and known `sudo` privilege escalation exploit attempt
-   su to root
-   Potential Reverse Shell

### Event 1 - Critical File Modification - auth related files

#### What is Monitored

Any update to critical authentication files, including `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`, and `/etc/sudoers`.

#### Why it's Important

These files control all user accounts, password hashes, group memberships, and sudo privileges. An unauthorized modification is one of the most severe signs of a system compromise.

#### Threats Detected

-   Persistence: An attacker adding a new user account to maintain access.
-   Privilege Escalation: An attacker adding their user to the root or sudo group.
-   Tampering: An attacker attempting to cover their tracks or disrupt system access.

#### How it's Monitored

I use Linux auditd service and configured it with rules to watch these specific files. The script then uses ausearch to find events tagged with the `auth_file_change` key. It then checks if the program that made the change is on a pre-defined whitelist of standard system tools (e.g., `/usr/bin/passwd`). If the modifying program is not on the whitelist (e.g., `sh`, `vim`, `dash`), an alert is generated.

#### Simple Test Case

```bash
# This command uses the 'sh' shell to append a comment to the passwd file,
# which is not a whitelisted program. This will trigger an alert.
sudo sh -c "echo '# Sentinel Test' >> /etc/passwd"

# However, if you use a normal passwd to update the /etc/shadow
# The alert will not be trigger since we whitelisted the bin
passwd
```

#### Limitations & False Positives:

-   An alert will be triggered if a system administrator manually edits one of these files with a text editor like vim or nano. While technically a "false positive," this is often desired behavior, as manual edits should be rare and scrutinized.
-   Legitimate but non-standard system management tools (like Ansible, Puppet, or custom scripts) that modify these files will trigger alerts unless they are added to the whitelist in the script.

### Event 2 - Cron Job Creation or Modification

#### What is Monitored

Creation or modification of files within system-wide and user-specific cron directories (`/etc/crontab`, `/etc/cron.d/`, `/var/spool/cron/`).

#### Why it's Important

Cron is the most common and effective technique for an attacker to achieve persistence on a Linux system. By placing a script in a cron directory, they can ensure their malicious code is executed repeatedly, even after a reboot.

#### Threats Detected

-   Persistence: Scheduling a reverse shell, malware downloader, or data exfiltration script to run on a recurring basis.

#### How it's Monitored

Same with auth files, auditd rules are set to watch the relevant cron files and directories with the key cron_file_change. The sentinel uses ausearch to find these events. Since any unexpected change to system scheduling is suspicious, all modifications trigger an alert.

#### Simple Test Case

```bash
# This command creates a new, empty file in a cron directory,
# simulating an attacker adding a new scheduled task.
sudo touch /etc/cron.d/sentinel-test-job
```

#### Limitations & False Positives:

Legitimate software packages or system updates that add cron jobs will trigger an alert. This is generally useful, as it informs the administrator of new scheduled tasks on the system.
Administrators adding their own legitimate cron jobs will also trigger alerts, which is expected behavior.

### Event 3 - Failed Sudo Attempts and known `sudo` privilege escalation exploit attempt

#### What is Monitored

Logs indicating a user tried to execute a command with sudo but failed authentication (e.g., by providing the wrong password). Additional, a specific sudo command pattern (sudo -u#-1 ... or sudo -u#4294967295 ...) is monitored. This pattern exploits a known vulnerability (CVE-2019-14287) that allows a user to run a command as root, even if their sudoer permissions explicitly deny it.

#### Why it's Important

A high volume of failed attempts can indicate a brute-force attack against a user's password. A single attempt from an unexpected user can indicate an attacker with low-level access trying to escalate their privileges.

#### Threats Detected

-   Privilege Escalation Attempts.
-   Password Brute-Force Attacks.

#### How it's Monitored

The script reads the systemd journal for sudo events (journalctl \_COMM=sudo) and looks for log messages containing phrases like "authentication failure" or "NOT in sudoers". For the CVE-2019-14287, we can simply inspects the command field of sudo events from the systemd journal, searching for the exact exploit string.

#### Simple Test Case

```bash
# This command attempts to run 'ls' with sudo but intentionally pipes
# the wrong password, guaranteeing an authentication failure.
echo "wrongpassword" | sudo -S ls
# This command attempts to run the 'id' command using the exploit.
# It will trigger the alert regardless of whether it succeeds.
sudo -u#-1 id > /dev/null 2>&1 || true
```

#### Limitations & False Positives

The most common false positive is a legitimate user simply forgetting their password. The value of this alert is in its frequency and context. A single failure is low-priority, but many failures in a short period are a high-priority event.

### Event 4 - su to root

#### What is Monitored

System logs indicating that a user has successfully used the su (substitute user) command to open a new interactive session as the root user.

#### Why it's Important:

This event represents a direct and total privilege escalation. Unlike sudo, which typically grants temporary, command-specific privileges and logs every action, su provides a full, unaudited root shell. Once a user becomes root via su, their subsequent actions within that shell are not logged with their original user identity. Because it creates an accountability gap, many corporate security policies forbid or heavily discourage the use of su in favor of the more granular and auditable sudo. Monitoring for this event is therefore critical for both security and compliance.

#### Threats Detected

-   Privilege Escalation: An attacker or a compromised non-privileged user gaining full administrative control over the system.
-   Insider Threat: A legitimate user performing actions outside of their normal duties or trying to hide their tracks.
-   Accountability Gap: Creates a crucial audit trail for a high-privilege event that is otherwise difficult to track.

#### How it's Monitored

Just like event 3, it specifically queries for logs generated by the su binary (journalctl \_COMM=su) and parses the output to find the exact log message "session opened for user root". When detected, it also attempts to extract the name of the original user who initiated the command.

#### Simple Test Case:

```bash
su -
```

#### Limitations & False Positives

This detection has a very low rate of "false positives" in the traditional sense, as it will only trigger on an actual, successful su to root. However, it's important to understand the context:

-   It is an Auditing Alert: The alert itself does not distinguish between a legitimate system administrator using su and a malicious actor. Its purpose is to make you aware that this high-privilege event occurred.
-   In environments where administrators regularly use su as part of their workflow, these alerts will be common. T

### Event 5 - Potential Reverse Shell

#### What is Monitored

Common shell processes (bash, sh, nc, python, etc.) where the standard input, standard output, and standard error file descriptors are all pointing to the same network socket.

#### Why it's Important

This is the classic signature of an interactive reverse shell, which is an attacker's primary tool for gaining remote, interactive control over a compromised machine.

#### Threats Detected:

-   Remote Code Execution.
-   Command & Control (C2) Channel.

#### How it's Monitored

The script uses the psutil library to iterate through running processes. For each suspicious process, it inspects its file descriptors in the /proc filesystem to see if they are linked to a socket, indicating a network connection is driving the shell.

#### Simple Test Case

```bash
# In one terminal, start a listener:
nc -l -p 9001
# In a second terminal, execute the reverse shell:
bash -i >& /dev/tcp/127.0.0.1/9001 0>&1
```

#### Limitations & False Positives

This detection is heuristic and may not detect more advanced or obfuscated reverse shells (e.g., those using encrypted C2 channels or custom-built tools).
While very rare, some legitimate applications might use I/O redirection in a way that mimics this pattern, which could lead to a false positive.
