audit.md

# Linux Security Audit Script

## Overview

This script is designed to perform a comprehensive security audit on a Linux system. It checks user and group configurations, file and directory permissions, running services, firewall status, network settings, and more. The script also includes hardening functions to enhance system security.

## Features

- **User and Group Audit**: Identifies human users, groups, and checks for non-root UID 0 users.
- **File and Directory Permission Audit**: Checks for world-writable files and directories, as well as SSH directory permissions.
- **Service Audit**: Lists running services and checks for unauthorized or unexpected services.
- **Firewall Audit**: Verifies the status of firewall services and lists open ports.
- **Network Audit**: Displays public and private IP addresses and checks SSH port exposure.
- **Update Audit**: Checks for available security updates and ensures automatic updates are enabled.
- **Log Monitoring**: Monitors SSH login attempts and suspicious activity.
- **Hardening Functions**: Provides options to harden SSH, disable IPv6, secure GRUB, configure firewall rules, and enable automatic security updates.

## Prerequisites

- A Linux-based operating system (Ubuntu recommended).
- `bash` shell.
- `sudo` privileges for certain operations.
- Required packages: `awk`, `curl`, `iptables`, `ss`, `systemctl`, `grep`, `sed`, `ssh-keygen`.

## Usage

1. **Clone the Repository** (if applicable):
   ```bash
   git clone <repository-url>
   cd <repository-directory>
   ```

2. **Make the Script Executable**:
   ```bash
   chmod +x audit.sh
   ```

3. **Run the Script**:
   You can run the script with various options. Here are some examples:
   - To perform a user and group audit:
     ```bash
     ./audit.sh --useraudit
     ```
   - To check file and directory permissions:
     ```bash
     ./audit.sh --permcheck
     ```
   - To run all audits:
     ```bash
     ./audit.sh --all
     ```
   - To access the interactive hardening menu:
     ```bash
     ./audit.sh --hardening
     ```

4. **Help**:
   For a list of available options, run:
   ```bash
   ./audit.sh --help
   ```

## Hardening Menu Options

The hardening menu provides the following options:
1. **SSH Key-based Authentication & Root Hardening**
2. **Disable IPv6 & Hardening for SafeSquid**
3. **Secure GRUB/Bootloader**
4. **Firewall (Recommended iptables Rules)**
5. **Automatic Security Updates**
6. **ALL Hardening Steps**

## Important Notes

- Ensure you have backups of important data before running the script, especially when applying hardening changes.
- Review the output of each audit carefully to understand the security posture of your system.
- Modify the script as necessary to fit your specific environment and security policies.
