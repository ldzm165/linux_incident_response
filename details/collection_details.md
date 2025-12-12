## Requirements
- **Linux Distributions**: Debian/Ubuntu, RHEL/CentOS, Fedora, or compatible distributions
- **Administrator privileges** (root/sudo recommended for full collection)
- **Standard Linux utilities** (coreutils, net-tools, lsof, etc.)
- **Minimum disk space**: 50-200MB for evidence storage

## Evidence Collection Details

### What Gets Collected (9 Logical Categories)

#### 1. System Information (`01_system_information.txt`)
- Collection timestamp and system time
- Operating system details and distribution
- System uptime and boot time
- Kernel version and hardware information
- Timezone and clock configuration

#### 2. User and Authentication Information (`02_user_authentication.txt`)
- All user accounts from `/etc/passwd`
- Password hashes from `/etc/shadow` (when accessible)
- User groups and memberships
- Sudoers configuration and privileges
- Currently logged in users and sessions
- Recent login history and failed attempts
- Files with no owner (orphaned files)

#### 3. Process and Service Information (`03_process_service_info.txt`)
- All running processes with full details
- Process hierarchy and parent-child relationships
- Processes with network connections
- Listening ports and associated services
- System service status (systemd/SysV init)
- Cron jobs and scheduled tasks
- System startup configurations

#### 4. Network Configuration (`04_network_configuration.txt`)
- Network interfaces and IP configuration
- Routing tables and gateway information
- ARP cache entries
- DNS configuration and hosts file
- Active network connections (TCP/UDP)
- Listening ports and established sessions
- Network statistics and interface details

#### 5. Security Configuration (`05_security_configuration.txt`)
- Firewall status (UFW, iptables, firewalld)
- Security modules status (SELinux, AppArmor)
- SUID/SGID executable files
- World-writable files and directories
- File permission configurations
- Authentication policies

#### 6. File System and Logs (`06_filesystem_logs.txt`)
- Disk usage and mounted filesystems
- Recently modified system files
- Critical directory listings (/etc, /bin, /tmp, /var)
- Log directory overview and permissions
- Authentication log snippets
- System log excerpts
- Key log file access

#### 7. Package and Kernel Information (`07_package_kernel_info.txt`)
- Installed packages (dpkg/rpm based systems)
- Recently installed software
- Loaded kernel modules
- Available kernel modules
- Package manager logs
- Software repository information

#### 8. Triage Summary (`08_triage_summary.txt`)
- **CRITICAL FINDINGS**: Immediate indicators of compromise
- Suspicious process names (miners, backdoors, reverse shells)
- Unusual listening ports (4444, 5555, 13337, 31337)
- SSH authorized keys for all users
- User command history review
- Modified SUID/SGID binaries
- Non-standard or hidden processes

#### 9. Log Archive (`var_log_backup.tar.gz`)
- Complete `/var/log` directory backup
- Authentication logs (auth.log, secure)
- System logs (syslog, messages)
- Kernel logs (kern.log)
- Application-specific logs
- Historical log files

### Supporting Files
- `00_collection_log.txt` - Execution log with timestamps and command output
- `00_collection_summary.txt` - Collection metadata and file inventory
- `file_hashes.md5` - Integrity verification hashes (MD5)
- `logs/` - Directory with copied log files
- `errors.log` - Any errors encountered during collection

## Usage Instructions

### Standard Collection
```bash
# Make the script executable
chmod +x ir_linux.sh

# Run with sudo for complete collection
sudo ./ir_linux.sh

# Or without sudo (some commands will be limited)
./ir_linux.sh
