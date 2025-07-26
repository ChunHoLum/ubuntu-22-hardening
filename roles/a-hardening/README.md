# A. Basic Security Hardening of a Public-Facing Server

This role is aimed to apply foundational hardening to a fresh Ubuntu 22.04 server with a public IP address. The goal is to establish a baseline of security to mitigate the most common and immediate threats faced by internet-exposed systems.

> Note: Controls for SSH hardening and for monitoring/detection are considered out of scope for this playbook and are assumed to be handled by separate role (b & c).

## How to use this role

You can run this role via the core provisioner playbook [readme.md](/README.md)

## Security Philosophy & Threat Model

A server with a public IP address is immediately and continuously exposed to a global threat landscape dominated by automated, opportunistic attacks. These are not sophisticated, targeted campaigns but rather high-volume scans from bots and scripts looking for "low-hanging fruit."

The primary threats can be prioritized as follows:

-   Automated Service Exploitation: Bots constantly scan IP ranges for open ports and known vulnerabilities in common services (web servers, databases, caches). The goal is to gain an initial foothold.
-   Denial of Service (DoS): Attacks aimed at exhausting server resources (CPU, memory, network bandwidth) to make legitimate services unavailable.
-   Resource Hijacking: Once compromised, the server's resources are used for malicious purposes like crypto-mining, sending spam, or participating in larger DDoS botnets.

The security design is therefore based on a layered, "defense-in-depth" strategy that directly counters these primary external threats.

## Chosen Security Controls

The following three controls were chosen to provide the most significant security improvement for the effort involved.

### 1. Control: Firewall

#### Rationale

A properly configured firewall serves as the primary perimeter defense for any public-facing server. It acts as a gatekeeper, controlling which network traffic is allowed to reach the server based on predefined rules. By default, a fresh Ubuntu installation exposes all services to the internet, creating an unnecessarily large attack surface. A firewall dramatically reduces this exposure by implementing the principle of "default deny" - blocking all traffic except what is explicitly required for the server's intended function.

#### Threat Mitigation

This control directly addresses multiple threat vectors:

-   Automated service recon/enumerate by botnet
-   Denial of service: ufw have default rate limiting and only allow traffic from whitelist sources, providing the first line of defense against volumetric attacks.

#### Implementation Overview

The implementation will use Ubuntu's UFW (Uncomplicated Firewall), which provides a user-friendly interface to the underlying iptables/netfilter framework:

Enable UFW with a default policy of "deny incoming, allow outgoing" - this immediately blocks all unsolicited inbound connections while permitting the server to initiate outbound connections for updates and other operations.
Configure essential rules for management access (SSH on port 22) with default rate limiting to prevent brute-force attacks.
Enable UFW logging to maintain an audit trail of blocked connection attempts.
Ensure UFW is enabled at boot time for persistent protection.
The configuration will be templated to allow for role-specific customization while maintaining secure defaults.

#### Potential Drawbacks

Using IP-based firewall rules alone, like UFW, makes it hard to block all internet traffic because many services don’t use fixed IPs (egress espcailly). For example, package repositories, DNS servers, and NTP services often use big cloud systems that change IPs or share them across different services. Blocking one IP could break something you actually need. Also, most traffic is encrypted now, so it’s hard to see what’s inside just by IP. That’s why using something like a transparent proxy might help in this situation.

### 2. Control: Automated Security Patching

#### Rationale

The overwhelming majority of successful cyberattacks exploit known vulnerabilities for which a patch is already available. Manual patching is often slow, inconsistent, and prone to human error. Automating the application of security updates is the single most effective measure to close the window of opportunity for attackers.

#### Threat Mitigation

This control directly mitigates the threat of Exploitation of Known Vulnerabilities. Attack toolkits and botnets are rapidly updated to leverage newly disclosed vulnerabilities in software like the Linux kernel, OpenSSL, or web server daemons. An unpatched server is a primary target. Automated patching ensures that security fixes are applied promptly, often before automated exploits are widely deployed.

#### Implementation Overview

The solution leverages Ubuntu's native unattended-upgrades package, which is designed specifically for this task.

-   Use the package manager module to update the package cache.
-   Apply all available updates classified as "security" patches.
-   Include a handler to automatically reboot the server if a core component (like the kernel) is updated, as a restart is required for the patch to become effective.

#### Potential Drawbacks

The main drawback is the risk of service disruption from a faulty update. Although rare for security patches, an update could introduce a regression or an incompatibility with the running application. This risk is generally considered far lower than the risk of compromise. In a larger environment, this risk is managed by testing updates in a staging environment first.

### 3. Control: Kernel Parameter Hardening (System Core Integrity)

#### Rationale

The Linux kernel's default settings are optimized for general-purpose use and compatibility, not maximum security. Tuning the kernel's runtime parameters (via sysctl) provides a deeper layer of defense against network-level attacks and prevents the operating system from leaking information that could aid an attacker.

#### Threat Mitigation

This control hardens the system against various Network-Level Attacks and Information Leakage that a firewall alone does not address. I have config some common and key kernel setting to mitigate the following attacks:

-   SYN Flood DoS Attacks: Enabling SYN cookies allows the kernel to handle massive volumes of connection requests without exhausting memory.
-   IP Spoofing: Enabling reverse path filtering instructs the kernel to drop packets that appear to originate from an invalid source address.
-   Network Reconnaissance: Disabling responses to ICMP redirects and broadcast pings prevents attackers from mapping the internal network or using the server in amplification attacks.

#### Implementation Overview

A dictionary of recommended security-focused sysctl settings will be defined as an Ansible variable. Most of the kernel hardening standard follow CIS benchmark and best practices.

The playbook will apply these settings to the live kernel.

The settings will be persisted to a file in /etc/sysctl.d/ to ensure they are automatically re-applied on every boot.

#### Potential Drawbacks

The main risk is breaking legitimate but niche network functionality. For example, very strict reverse path filtering can interfere with some advanced, multi-homed network configurations. Each parameter must be understood to avoid inadvertently impacting performance or connectivity for legitimate use cases.
