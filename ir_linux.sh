#!/bin/bash
# ============================================
# Linux Incident Response Evidence Collection Script
# ============================================

# Configuration
HOSTNAME=$(hostname)
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
EVIDENCE_DIR="/tmp/ir_evidence_${HOSTNAME}_${TIMESTAMP}"
COLLECTION_LOG="${EVIDENCE_DIR}/00_collection_log.txt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'  # No Color

# Functions
log_action() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$COLLECTION_LOG"
    echo -e "${GREEN}[+]${NC} $1"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" >> "$COLLECTION_LOG"
    echo -e "${RED}[-] ERROR:${NC} $1"
}

add_section_header() {
    local file="$1"
    local title="$2"
    echo "" >> "$file"
    echo "============================================" >> "$file"
    echo "$title" >> "$file"
    echo "============================================" >> "$file"
    echo "Collection Time: $(date)" >> "$file"
    echo "Hostname: $HOSTNAME" >> "$file"
    echo "" >> "$file"
}

collect_data() {
    local file="$1"
    local title="$2"
    local command="$3"

    log_action "Collecting: $title"
    add_section_header "$file" "$title"

    # Execute command and handle errors
    if eval "$command" >> "$file" 2>> "${EVIDENCE_DIR}/errors.log"; then
        echo "Status: Success" >> "$file"
    else
        echo "Status: Partial or Failed - check errors.log" >> "$file"
        log_error "Command may have failed: $title"
    fi
    echo "" >> "$file"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${YELLOW}[!] Warning: Not running as root. Some commands may fail.${NC}"
    echo -e "${YELLOW}[!] Consider running with sudo.${NC}"
    # Exit the script if not root
    exit 1
fi

# Create evidence directory
log_action "Creating evidence directory: $EVIDENCE_DIR"
mkdir -p "$EVIDENCE_DIR" || {
    log_error "Failed to create directory. Exiting."
    exit 1  # Exit if directory creation fails
}

# Create logs
echo "Linux Incident Response Evidence Collection" > "$COLLECTION_LOG"
echo "Started: $(date)" >> "$COLLECTION_LOG"
echo "Hostname: $HOSTNAME" >> "$COLLECTION_LOG"
echo "Evidence Directory: $EVIDENCE_DIR" >> "$COLLECTION_LOG"
echo "============================================" >> "$COLLECTION_LOG"

# 1. SYSTEM INFORMATION
SYS_INFO="${EVIDENCE_DIR}/01_system_information.txt"

collect_data "$SYS_INFO" "Collection Date and Time" "date"
collect_data "$SYS_INFO" "System Uptime" "uptime"
collect_data "$SYS_INFO" "Hostname and OS Info" "uname -a"
collect_data "$SYS_INFO" "OS Release Information" "cat /etc/os-release"
collect_data "$SYS_INFO" "Kernel Version" "cat /proc/version"
collect_data "$SYS_INFO" "Boot Time" "last reboot" # More reliable than 'who -b'
collect_data "$SYS_INFO" "System Clock vs Hardware Clock" "echo 'System:'; date; echo 'Hardware:'; hwclock --show 2>/dev/null || echo 'hwclock not available'"
collect_data "$SYS_INFO" "Time Zone" "timedatectl status 2>/dev/null || cat /etc/timezone 2>/dev/null || echo 'Cannot determine timezone'"

# 2. USER AND AUTHENTICATION INFORMATION
USER_INFO="${EVIDENCE_DIR}/02_user_authentication.txt"

collect_data "$USER_INFO" "Current User and Privileges" "echo 'Current User:'; whoami; echo ''; echo 'Effective User/Group:'; id; echo ''; echo 'Sudo Status:'; sudo -n -l 2>/dev/null || echo 'Not in sudoers or password required'"
collect_data "$USER_INFO" "All User Accounts" "cat /etc/passwd"
collect_data "$USER_INFO" "Password Hashes (Shadow File)" "cat /etc/shadow 2>/dev/null || echo 'Permission denied: /etc/shadow'"
collect_data "$USER_INFO" "User Groups" "cat /etc/group"
collect_data "$USER_INFO" "Sudoers Configuration" "cat /etc/sudoers 2>/dev/null | grep -v '^#' 2>/dev/null || echo 'Permission denied: /etc/sudoers'"
collect_data "$USER_INFO" "Currently Logged In Users" "w"  # 'w' is more informative than 'who -a'
collect_data "$USER_INFO" "Last Logins" "lastlog 2>/dev/null || echo 'lastlog command not available'"
collect_data "$USER_INFO" "Recent Logins" "last -a"
collect_data "$USER_INFO" "Failed Login Attempts" "auth.log | grep \"Failed password\" | head -50 2>/dev/null || echo 'Failed login attempts not found'" #More specific search.
collect_data "$USER_INFO" "Users with Login Shells" "grep -v '/nologin\|/false' /etc/passwd | cut -d: -f1"
collect_data "$USER_INFO" "Files with No Owner" "find / -nouser -print 2>/dev/null | head -50"

# 3. PROCESS AND SERVICE INFORMATION
PROCESS_INFO="${EVIDENCE_DIR}/03_process_service_info.txt"

collect_data "$PROCESS_INFO" "All Running Processes (Full)" "ps aux"
collect_data "$PROCESS_INFO" "Process Tree" "pstree -p 2>/dev/null" # -p shows PIDs
collect_data "$PROCESS_INFO" "Processes with Network Connections" "ss -tulpn 2>/dev/null | head -100 || echo 'lsof not available'" #ss is generally preferred over lsof
collect_data "$PROCESS_INFO" "Listening Ports" "ss -tulpn 2>/dev/null"
collect_data "$PROCESS_INFO" "All Services Status" "systemctl list-units --type=service --all 2>/dev/null"
collect_data "$PROCESS_INFO" "Enabled Services" "systemctl list-unit-files --type=service --state=enabled 2>/dev/null"
collect_data "$PROCESS_INFO" "Cron Jobs" "echo 'System Crontab:'; cat /etc/crontab 2>/dev/null; echo ''; echo 'Cron Directories:'; ls -la /etc/cron.*/ 2>/dev/null; echo ''; echo 'User Crontabs:'; ls -la /var/spool/cron/ 2>/dev/null"

# 4. NETWORK CONFIGURATION
NETWORK_INFO="${EVIDENCE_DIR}/04_network_configuration.txt"

collect_data "$NETWORK_INFO" "Network Interfaces" "ip addr show"
collect_data "$NETWORK_INFO" "Routing Table" "ip route show"
collect_data "$NETWORK_INFO" "ARP Cache" "ip neigh show"
collect_data "$NETWORK_INFO" "DNS Configuration" "cat /etc/resolv.conf"
collect_data "$NETWORK_INFO" "Hosts File" "cat /etc/hosts"
collect_data "$NETWORK_INFO" "Active Network Connections" "ss -tunap"
collect_data "$NETWORK_INFO" "Established Connections" "ss -tn state established"
collect_data "$NETWORK_INFO" "Network Statistics" "ss -s"

# 5. SECURITY CONFIGURATION
SECURITY_INFO="${EVIDENCE_DIR}/05_security_configuration.txt"

collect_data "$SECURITY_INFO" "Firewall Status (UFW)" "ufw status numbered 2>/dev/null || echo 'UFW not installed'"
collect_data "$SECURITY_INFO" "Firewall Status (iptables)" "iptables -L -n -v 2>/dev/null || echo 'iptables not available'"
collect_data "$SECURITY_INFO" "Firewall Status (firewalld)" "firewall-cmd --state 2>/dev/null && firewall-cmd --list-all 2>/dev/null || echo 'firewalld not active'"
collect_data "$SECURITY_INFO" "SELinux Status" "sestatus 2>/dev/null || echo 'SELinux not installed'"
collect_data "$SECURITY_INFO" "AppArmor Status" "apparmor_status 2>/dev/null || echo 'AppArmor not installed'"
collect_data "$SECURITY_INFO" "SUID/SGID Files" "find / -type f -perm /4000 2>/dev/null"
collect_data "$SECURITY_INFO" "World-Writable Files" "find / -type f -perm -o+w -print 2>/dev/null"

# 6. FILE SYSTEM AND LOGS
FILESYSTEM_INFO="${EVIDENCE_DIR}/06_filesystem_logs.txt"

collect_data "$FILESYSTEM_INFO" "Disk Usage" "df -h"
collect_data "$FILESYSTEM_INFO" "Mounted Filesystems" "mount"
collect_data "$FILESYSTEM_INFO" "Recent Modified Files (System)" "find /etc /bin /sbin /usr/bin /usr/sbin -type f -mmin -60 2>/dev/null | head -50"  # Last 60 minutes
collect_data "$FILESYSTEM_INFO" "Critical Directory Listings" "for dir in /etc /bin /sbin /tmp /var/tmp; do echo \"=== \$dir ===\"; ls -la \$dir 2>/dev/null | head -20; done"
collect_data "$FILESYSTEM_INFO" "Log Directory Overview" "ls -la /var/log/"
collect_data "$FILESYSTEM_INFO" "Recent Authentication Logs" "tail -100 /var/log/auth.log 2>/dev/null || tail -100 /var/log/secure 2>/dev/null || echo 'Auth logs not found'"
collect_data "$FILESYSTEM_INFO" "System Log Snippet" "journalctl -n 50 2>/dev/null" #Use journalctl if available.

# 7. PACKAGE AND KERNEL INFORMATION
PACKAGE_INFO="${EVIDENCE_DIR}/07_package_kernel_info.txt"

collect_data "$PACKAGE_INFO" "Installed Packages (DPKG)" "dpkg -l 2>/dev/null | head -100 || echo 'dpkg not available'"
collect_data "$PACKAGE_INFO" "Installed Packages (RPM)" "rpm -qa 2>/dev/null | head -100 || echo 'rpm not available'"
collect_data "$PACKAGE_INFO" "Recently Installed Packages" "grep 'install ' /var/log/dpkg.log 2>/dev/null | tail -20 || echo 'dpkg log not found'"
collect_data "$PACKAGE_INFO" "Kernel Modules (Loaded)" "lsmod"
collect_data "$PACKAGE_INFO" "Kernel Modules (All)" "find /lib/modules/ -name '*.ko' 2>/dev/null"

# 8. TRIAGE SUMMARY (CRITICAL FINDINGS)
TRIAGE_INFO="${EVIDENCE_DIR}/08_triage_summary.txt"

collect_data "$TRIAGE_INFO" "CRITICAL: Suspicious Processes" "ps aux | grep -i -E 'miner|backdoor|shell|reverse|bind|perl|python|nc|netcat|telnet|8888|4444|1337'"
collect_data "$TRIAGE_INFO" "CRITICAL: Unusual Listening Ports" "ss -tulpn | grep -E ': (1433|3389|4444|5555|6666|7777|8888|9999|1337|31337)'"
collect_data "$TRIAGE_INFO" "CRITICAL: SSH Authorized Keys" "find /home /root -name 'authorized_keys' -type f -exec echo '=== {} ===' \; -exec cat {} \;"
collect_data "$TRIAGE_INFO" "CRITICAL: History Files" "for user in /home/* /root; do [ -d \"\$user\" ] && echo \"=== \$user/.bash_history ===\" && tail -20 \"\$user/.bash_history\" 2>/dev/null; done"
collect_data "$TRIAGE_INFO" "CRITICAL: SUID Binaries Changes" "find / -type f -perm /4000"

# 9. LOG COLLECTION (COMPRESSED)
log_action "Copying and compressing log files..."
LOG_DIR="${EVIDENCE_DIR}/logs"
mkdir -p "$LOG_DIR"

# Copy important log files
for log_file in /var/log/{auth.log,auth.log*,secure*,syslog,syslog*,messages*,boot.log,kern.log}; do
    if [ -f "$log_file" ]; then
        cp "$log_file" "$LOG_DIR/" 2>/dev/null && log_action "Copied: $(basename "$log_file")" || log_error "Failed to copy: $log_file"
    fi
done

# Create compressed archive
tar -czf "${EVIDENCE_DIR}/var_log_backup.tar.gz" -C /var/log . 2>/dev/null && \
    log_action "Created compressed log archive" || \
    log_error "Failed to create log archive"

# FINALIZATION
log_action "Creating file integrity hashes..."
find "$EVIDENCE_DIR" -type f -name "*.txt" -exec sha256sum {} \; > "${EVIDENCE_DIR}/file_hashes.sha256" 2>/dev/null

# Create summary file
SUMMARY_FILE="${EVIDENCE_DIR}/00_collection_summary.txt"
echo "============================================" > "$SUMMARY_FILE"
echo "LINUX INCIDENT RESPONSE COLLECTION COMPLETE" >> "$SUMMARY_FILE"
echo "============================================" >> "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"
echo "Collection Details:" >> "$SUMMARY_FILE"
echo "------------------" >> "$SUMMARY_FILE"
echo "Hostname: $HOSTNAME" >> "$SUMMARY_FILE"
echo "Collection Time: $(date)" >> "$SUMMARY_FILE"
echo "Evidence Directory: $EVIDENCE_DIR" >> "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"
echo "Files Collected:" >> "$SUMMARY_FILE"
echo "---------------" >> "$SUMMARY_FILE"
ls -la "$EVIDENCE_DIR"/*.txt >> "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"
echo "Total Evidence Files:" >> "$SUMMARY_FILE"
find "$EVIDENCE_DIR" -type f -name "*.txt" | wc -l >> "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"
echo "Collection completed at: $(date)" >> "$SUMMARY_FILE"
echo "============================================" >> "$SUMMARY_FILE"

# Final output
echo ""
echo "============================================"
echo "COLLECTION COMPLETE"
echo "============================================"
echo ""
echo -e "${GREEN}Evidence stored in:${NC} $EVIDENCE_DIR"
echo ""
echo "Files Created:"
echo "-------------"
ls -1 "$EVIDENCE_DIR"/*.txt | xargs -n1 basename
echo ""
echo -e "${YELLOW}Review the triage summary first:${NC}"
echo "    $EVIDENCE_DIR/08_triage_summary.txt"
echo ""
echo -e "${YELLOW}For detailed analysis, check:${NC}"
echo "    01_system_information.txt - System basics"
echo "    02_user_authentication.txt - User accounts"
echo "    03_process_service_info.txt - Running processes"
echo "    04_network_configuration.txt - Network info"
echo ""
echo "File integrity hashes saved in:"
echo "    file_hashes.sha256"
echo ""
echo -e "${GREEN}To preserve chain of custody, note this path:${NC}"
echo "    $EVIDENCE_DIR"
echo ""
