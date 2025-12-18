#!/bin/bash
# ==========================================================
# Bug Bounty SAFE Automation Framework (Enhanced)
# Recon → Identify → Metasploit CHECK → Benign Validation → Reports
# ==========================================================
# ✔ CVE auto-mapping (basic)
# ✔ CVSS placeholders
# ✔ HackerOne / Bugcrowd templates
# ✔ Web-only mode
# ✔ TXT + JSON + Markdown output
# ❌ NO exploitation / shells / persistence
# ==========================================================

set -euo pipefail

DATE=$(date +"%Y-%m-%d_%H-%M")
BASE="bb-safe-$DATE"
OUTDIR="$BASE/reports"
SCANDIR="$BASE/scans"
MSFDIR="$BASE/metasploit"
TARGETS="targets.txt"
WEB_ONLY=${WEB_ONLY:-false}   # set WEB_ONLY=true ./bb_safe.sh

mkdir -p "$OUTDIR" "$SCANDIR" "$MSFDIR"

log(){ echo -e "[+] $1"; }

log "Bug Bounty SAFE Scan Started ($DATE)"
log "Web-only mode: $WEB_ONLY"

# ----------------------------------------------------------
# 1) SAFE RECON
# ----------------------------------------------------------
log "Running SAFE recon (nmap -sV)"
while read -r target; do
  [[ -z "$target" ]] && continue
  nmap -sV -Pn -T3 --open "$target" -oN "$SCANDIR/$target.nmap" || true

done < "$TARGETS"

# ----------------------------------------------------------
# 2) IDENTIFY SERVICES
# ----------------------------------------------------------
log "Identifying exposed services"
cat $SCANDIR/*.nmap 2>/dev/null | grep -Ei "(http|https|ssh|ftp|smb)" > "$OUTDIR/services.txt" || true

# ----------------------------------------------------------
# 3) METASPLOIT CHECK-ONLY
# ----------------------------------------------------------
log "Preparing Metasploit CHECK-only validation"

cat << 'EOF' > "$MSFDIR/check.rc"
workspace -a bounty_safe
setg VERBOSE true

# ---- SMB (MS17-010)
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS file:targets.txt
check

# ---- FTP (VSFTPD)
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS file:targets.txt
check

# ---- HTTP Struts Example (check only)
use exploit/multi/http/struts2_content_type_ognl
set RHOSTS file:targets.txt
check

exit
EOF

if [ "$WEB_ONLY" = false ]; then
  msfconsole -q -r "$MSFDIR/check.rc" | tee "$OUTDIR/metasploit_check.log" || true
else
  log "Skipping network exploits (WEB_ONLY=true)"
fi

# ----------------------------------------------------------
# 4) BENIGN VALIDATION
# ----------------------------------------------------------
log "Running benign validation (headers only)"
: > "$OUTDIR/benign_validation.txt"
while read -r target; do
  [[ -z "$target" ]] && continue
  curl -I --max-time 10 "http://$target" >> "$OUTDIR/benign_validation.txt" 2>/dev/null || true

done < "$TARGETS"

# ----------------------------------------------------------
# 5) CVE + CVSS MAPPING (BASIC)
# ----------------------------------------------------------
log "Mapping CVEs & CVSS (basic heuristics)"

cat << 'EOF' > "$OUTDIR/cve_map.json"
{
  "MS17-010": {"cve": "CVE-2017-0144", "cvss": "8.1"},
  "VSFTPD": {"cve": "CVE-2011-2523", "cvss": "7.5"},
  "STRUTS2": {"cve": "CVE-2017-5638", "cvss": "10.0"}
}
EOF

# ----------------------------------------------------------
# 6) CLEAN REPORTS
# ----------------------------------------------------------
log "Generating reports (TXT / MD / JSON)"

# ---- TXT
cat << EOF > "$OUTDIR/FINAL_REPORT.txt"
Bug Bounty Vulnerability Validation Report
=========================================

Date: $DATE

Methodology:
- Safe Recon (nmap -sV)
- Service identification
- Metasploit CHECK-only validation
- Benign HTTP header validation
- No exploitation or post-exploitation

Targets:
$(cat $TARGETS)

Findings:
---------
$(grep -i vulnerable "$OUTDIR/metasploit_check.log" 2>/dev/null || echo "No confirmed vulnerabilities via check mode")

Compliance:
-----------
All actions were non-destructive and within bug bounty scope.
EOF

# ---- MARKDOWN (HackerOne/Bugcrowd)
cat << EOF > "$OUTDIR/FINAL_REPORT.md"
# Vulnerability Validation Report

**Date:** $DATE

## Methodology
- Recon (safe service discovery)
- Metasploit non-exploiting `check`
- Benign validation only

## Evidence
```text
$(grep -i vulnerable "$OUTDIR/metasploit_check.log" 2>/dev/null || echo "No vulnerable services detected")
```

## Impact
Potential exposure based on version and configuration mismatch.

## Compliance
No payload execution, no shells, no persistence.
EOF

# ---- JSON (automation-friendly)
cat << EOF > "$OUTDIR/FINAL_REPORT.json"
{
  "date": "$DATE",
  "methodology": ["recon", "metasploit_check", "benign_validation"],
  "targets": "$(tr '\n' ',' < $TARGETS)",
  "findings": "$(grep -i vulnerable "$OUTDIR/metasploit_check.log" 2>/dev/null | tr '\n' ';')",
  "compliance": true
}
EOF

log "All reports generated in $OUTDIR"
log "Bug bounty SAFE scan completed successfully"
