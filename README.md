# Linux Incident Response & Evidence Collection Toolkit

## Overview
A professional, automated shell script for collecting comprehensive forensic evidence from Linux systems during security incidents. This tool gathers critical system, user, network, and security data in an organized, forensically sound manner for rapid analysis.

## Quick Start

### Basic Usage
```bash
# 1. Clone the repository
git clone https://github.com/ldzm165/linux_incident_response.git
cd linux_incident_response

# 2. Make the script executable
chmod +x ir_linux.sh

# 3. Run with sudo for complete data collection
sudo ./ir_linux.sh

# 4. First, review the triage summary for immediate threats
cat /tmp/ir_evidence_*/08_triage_summary.txt

#### Disclaimer: This tool is for authorized incident response and forensic investigations only. Use in compliance with all applicable laws and organizational policies.
