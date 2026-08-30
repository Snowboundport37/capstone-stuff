# Analyst Remediation Notes (WannaCry)

## 1) How To Interpret Findings

- `confidence_score 0-30`: exposed but not infected
- `confidence_score 31-70`: suspicious activity, escalate investigation
- `confidence_score 71-100`: likely or confirmed WannaCry infection
- Exact hash matches should be treated as confirmed malicious indicators.

## 2) When To Isolate The Host

Isolate immediately when one or more are present:
- active WannaCry process indicators (`@WanaDecryptor@.exe`, known sample process path/hash)
- `mssecsvc2.0` service indicator with suspicious startup behavior
- active SMB exposure plus multiple infection indicators
- rapid spread indicators across adjacent systems

Use containment controls:
- temporary SMB firewall blocking (`445/139`)
- optional host isolation (explicit switch only)

## 3) When To Reimage Instead Of Cleanup

Prefer full reimage when:
- active compromise is confirmed and host trust is high priority
- persistence and lateral movement are suspected beyond scoped artifacts
- encryption/impact is extensive and rollback confidence is low
- IR policy mandates gold-image restoration after ransomware events

## 4) How To Check Neighboring Systems For SMB Exposure

- identify hosts with SMBv1 enabled
- identify hosts listening on TCP `445`/`139` with weak segmentation
- verify patch state for MS17-010-era protections
- run audit mode toolkit at scale through approved enterprise orchestration

## 5) What To Send To Management

Provide a concise incident packet:
- executive summary (status, confidence, business impact)
- containment steps completed
- eradication actions completed
- remaining risk and confidence boundaries
- recovery plan (backup restore / reimage timeline)
- follow-up controls (patching, SMB hardening, credential hygiene, detection tuning)
