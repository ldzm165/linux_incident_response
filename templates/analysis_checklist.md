# Linux Incident Analysis Checklist

## Phase 1: Triage (0-15 minutes)
- [ ] Review `08_triage_summary.txt`
- [ ] Check for critical process names (miners, backdoors, reverse shells)
- [ ] Identify unusual listening ports (4444, 5555, 13337, 31337)
- [ ] Note SSH authorized keys in all user directories
- [ ] Review user command history excerpts
- [ ] Check for modified SUID/SGID binaries

## Phase 2: User Analysis (15-30 minutes)
- [ ] Review `02_user_authentication.txt`
- [ ] Identify unauthorized accounts in `/etc/passwd`
- [ ] Check for users with UID 0 (root equivalent)
- [ ] Review sudoers configuration for unusual privileges
- [ ] Analyze recent login sessions and failed attempts
- [ ] Check for files with no owner (orphaned files)

## Phase 3: Persistence (30-45 minutes)
- [ ] Analyze `03_process_service_info.txt`
- [ ] Check cron jobs (system and user)
- [ ] Review system service configurations
- [ ] Examine startup scripts and configurations
- [ ] Analyze installed kernel modules (`07_package_kernel_info.txt`)
- [ ] Check for malicious systemd services

## Phase 4: System Changes (45-60 minutes)
- [ ] Review `07_package_kernel_info.txt`
- [ ] Check recently installed software packages
- [ ] Review loaded kernel modules
- [ ] Analyze `06_filesystem_logs.txt` for recent file modifications
- [ ] Check world-writable files and directories
- [ ] Examine environment variables and PATH settings

## Phase 5: Network Activity (60-75 minutes)
- [ ] Review `04_network_configuration.txt`
- [ ] Analyze active network connections
- [ ] Identify unusual outbound connections
- [ ] Check DNS configuration for hijacking
- [ ] Review firewall rules and status
- [ ] Correlate network connections with suspicious processes

## Phase 6: Log Analysis (75-90 minutes)
- [ ] Review authentication logs (`logs/auth.log`, `logs/secure`)
- [ ] Analyze system logs for errors and warnings
- [ ] Check for log file tampering or missing logs
- [ ] Search for IOCs (IPs, domains, hashes) in all logs
- [ ] Correlate timestamps with suspicious activities

## Phase 7: Evidence Correlation & Timeline (90-120 minutes)
- [ ] Correlate user activity with network connections
- [ ] Map process execution to file modifications
- [ ] Create incident timeline from all evidence
- [ ] Document chain of custody and evidence integrity
- [ ] Prepare summary of findings and recommendations

## Additional Checks for Advanced Threats
- [ ] Check for hidden processes using `ps auxf` vs process list
- [ ] Verify integrity of critical system binaries
- [ ] Look for rootkit indicators in `/proc` and `/dev`
- [ ] Check for LD_PRELOAD hijacking
- [ ] Review SSH configuration for backdoors
- [ ] Verify system time consistency across all logs
