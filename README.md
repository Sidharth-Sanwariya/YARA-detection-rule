# YARA Detection Rules

Custom YARA rules for detecting malware patterns.

## Rules Included

- `suspicious.yar` - Contains 3 rules:
  - Suspicious_PowerShell (detects PowerShell download patterns)
  - Suspicious_Executable_Strings (detects suspicious strings in EXEs)
  - Crypto_Wallet_Stealer (detects crypto stealer patterns)

## Scan Results

Scanned Downloads folder on personal Windows machine.

Results: `scan_results.txt`

## False Positive Investigation

One match (`Anime wallpaper + Installer.exe`) was verified on VirusTotal:
- Detection: 0/90
- Verdict: False positive (safe file)

## Usage

```bash
yara64.exe suspicious.yar C:\Users\Sidha\Downloads\
