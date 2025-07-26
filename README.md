# Ubuntu 22.04 Hardening

A modular Ansible provisioner for Ubuntu 22.04 security hardening, detection scripts, and SSH 2FA configuration.

> Disclaimer: education purpose only! I am just trying to use Ansible and custom scripts to see what we can do to secure a ubuntu 22 servers...

## Prerequisite & Assumption

For simplicity, I assume this playbook will run inside the target host. (we can update `inventory/hosts.yml` if we want to do it remotely, but I didn't test it.)

The following things are required:

-   The user who runs the playbook require `root` account
-   python3 and ansible installed - `ansible-playbook --version`

```
ansible-playbook [core 2.17.13]
  config file = /home/ho/ubuntu-22-hardening/ansible.cfg
  configured module search path = ['/root/.ansible/plugins/modules', '/usr/share/ansible/plugins/modules']
  ansible python module location = /root/.local/lib/python3.10/site-packages/ansible
  ansible collection location = /root/.ansible/collections:/usr/share/ansible/collections
  executable location = /root/.local/bin/ansible-playbook
  python version = 3.10.12 (main, May 27 2025, 17:12:29) [GCC 11.4.0] (/usr/bin/python3)
  jinja version = 3.0.3
  libyaml = True
```

you can install ansible and pip via the following command

```bash
apt-get install python3-pip
python3 -m pip install --user ansible
```

## Usage

```sh
# Run all roles at once
ansible-playbook -i inventory/hosts.yml provisioner.yml
```

> Before you execute the role `c`, please ensure you have created a user and copy your own pubkey to the user `~/.ssh/authorized_keys` file`

```sh
# Run specific role(s) by tags, please refer to vars/roles to check all the avaliable tags
ansible-playbook -i inventory/hosts.yml provisioner.yml --tags a
ansible-playbook -i inventory/hosts.yml provisioner.yml --tags hardening
ansible-playbook -i inventory/hosts.yml provisioner.yml --tags b,c
```

## Roles

The following roles are self-contained with their own `README.md` to document all the controls and decision made.

### a-hardening

This role is for design for `A. Basic Security Hardening of a Public-Facing Server`.

The tags for this role is `a` or `hardening`.

Link to [README.md](/roles/a-hardening/README.md)

### b-detection

This role is design for `B. Script for Detecting Suspicious Admin Activity`.

The tags for this role is `b` or `detection`.

Link to [README.md](/roles/b-detection/README.md)

### c-ssh-with-2fa

This role is design for `C. Set Up SSH with 2FA (Key + OTP)`.

The tags for this role is `c` or `ssh-with-2fa`.

Link to [README.md](/roles/c-ssh-with-2fa/README.md)

## Feature & Core Design Decision

1. Single Entry Point

-   One provisioner.yml handles all execution

2. Tag-Based Execution

-   No tags = run everything
-   Tags filter which roles execute
-   Multiple tags per role for flexibility

3. Modular Roles

-   Each role is self-contained
-   Roles can be run independently
-   Easy to add/remove functionality

4. Future Extensibility

-   Inventory supports multiple hosts
-   Role structure supports complex deployments
