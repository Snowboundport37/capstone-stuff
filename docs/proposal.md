> This is the original proposal. For what we actually built, start at [Capstone, as built](../README.md).

**Project 1: Enterprise Proxmox Deployment for Malware Removal with Ansible**

---

## Problem Statement
Malware incidents in enterprise and educational networks continue to increase every year, creating higher costs for detection, response, and recovery. According to the 2024 Verizon Data Breach Investigations Report, the education sector remains one of the **top three targets for ransomware attacks**, with an average dwell time of **six days** before detection. At the same time, organizations are facing significant cost increases for proprietary virtualization platforms such as VMware vCenter. After Broadcom’s acquisition of VMware, licensing fees have risen sharply, with many institutions reporting **60–80% higher costs** for equivalent functionality.

Proxmox Virtual Environment (VE) is a powerful, open-source alternative to VMware that eliminates licensing fees while offering enterprise-grade virtualization features. However, setting up a secure Proxmox infrastructure and handling malware remediation across hosts and virtual machines (VMs) presents challenges. Malware infections can leave behind hidden artifacts—registry entries, scheduled tasks, startup services, or memory artifacts—even after antivirus cleanup. Manual remediation is slow, error-prone, and inconsistent.  

**Problem Summary:** Educational institutions and enterprises need a cost-effective, automated virtualization platform that allows safe malware testing, artifact detection, and rapid remediation while maintaining verified clean system baselines.

---

## Proposed Solution
This project will build an **enterprise-grade Proxmox virtualization lab** integrated with **Ansible automation** and open-source forensic tools. The lab will:
- Provide a **safe, segmented network** for controlled malware testing.
- Use forensic tools to detect malware artifacts across both Proxmox hosts and guest VMs.
- Employ **Ansible playbooks** to automate deployment, configuration, and artifact remediation, reducing human error and speeding recovery.
- Maintain a **golden image** for every VM and verify integrity with cryptographic hashing (SHA-256) to guarantee clean restoration after testing.

The environment will simulate a small enterprise network, enabling repeatable testing and demonstrating how automation can drastically improve malware response and reduce operational costs.

---

## Scope
The project will include the following:
1. **Infrastructure Setup**
   - Install Proxmox VE on a Dell PowerEdge R340 server.
   - Configure isolated network segments using a TP-Link AX5400 router and Cisco Catalyst 2960-CX switch.
   - Deploy network monitoring tools such as Zeek and DNS filtering with Pi-hole.

2. **Malware Testing**
   - Obtain and safely execute at least **three different malware samples** (e.g., ransomware, trojans, worms) within isolated VMs.
   - Collect and document forensic artifacts (file system changes, registry modifications, scheduled tasks, network logs, memory artifacts) using tools such as Zeek, KAPE, and volatility.

3. **Automation & Remediation**
   - Develop Ansible playbooks to:
     - Deploy hardened VM templates.
     - Detect and remediate malware artifacts automatically.
     - Revert systems to a golden image with hash-verified integrity.

4. **Golden Image Management**
   - Create and maintain clean VM images using FOG or similar imaging software.
   - Perform automated SHA-256 hash verification before and after each test to confirm image integrity.

**Out of Scope**
- Development of custom malware.
- Testing on non-Proxmox virtualization platforms.
- Live production deployment outside the lab environment.

---

## Expected Outcomes and Performance Goals
Based on published automation benchmarks and internal targets, the project aims to achieve the following measurable outcomes:

| Metric | Baseline (Manual) | Target with Proxmox + Ansible |
|-------|--------------------|------------------------------|
| **Mean Time to Remediation (MTTR)** | 3–5 days for artifact cleanup | **<24–48 hours** for full cleanup and verification |
| **Detection-to-Remediation Lead Time** | Several hours to days | **<1 hour** for automated playbook initiation |
| **Consistency of Artifact Removal** | ~70% success rate (human error) | **>90%** successful, repeatable artifact removal |
| **Parallel Remediation** | One VM at a time | Simultaneous remediation on **100% of affected VMs** |
| **Operational Cost Reduction** | High VMware licensing + labor | **60–80% lower software costs** + **50–70% fewer admin hours** |

Additional goals:
- Restore golden images and verify clean states in **under 3 hours** after each malware test.
- Produce a comprehensive **70+ page report** documenting methodology, artifacts discovered, remediation scripts, and performance metrics.

---

## Timeline
Weeks **1–3** – Install Proxmox VE, configure network segmentation, deploy monitoring tools, and collect malware samples.  
Weeks **4–7** – Execute malware samples in isolated VMs, collect forensic artifacts, and document all system changes.  
Weeks **8–10** – Develop and test Ansible playbooks for deployment, hardening, and automated remediation.  
Weeks **11–12** – Create golden VM images, integrate FOG imaging, and implement SHA-256 hash verification.  
Weeks **13–15** – Finalize documentation, compile the final report, and present a live demonstration of automated malware remediation.

---

## Equipment
- **Server:** Dell PowerEdge R340 (Proxmox host)
- **Router:** TP-Link AX5400 WiFi 6
- **Switch:** Cisco Catalyst 2960-CX
- **Monitoring Tools:** Zeek, Pi-hole, KAPE, Volatility
- **Automation Tools:** Ansible
- **Imaging Tools:** FOG server for golden image management
- **Power Management:** Kasa Smart WiFi Plug Mini for controlled power cycling

---

## Why This Matters
- **Cost Savings:** Moving from VMware to Proxmox provides **60–80% lower licensing costs** (SaturnME, 2024).  
- **Efficiency Gains:** Automated remediation has been shown to reduce MTTR by **up to 87%** compared to manual remediation (Tamnoon, 2024).  
- **Security Improvement:** Research shows malware artifacts such as registry changes and scheduled tasks often remain after antivirus cleanup, highlighting the need for automated detection and cleanup (JATIT, 2022).  
- **Career Relevance:** Skills in Proxmox, Ansible, and malware forensics are in high demand as organizations adopt open-source virtualization.

---

## References
- Verizon. (2024). *Data Breach Investigations Report*. https://www.verizon.com/business/resources/reports/dbir/  
- SaturnME. (2024). *How Proxmox Delivers Massive Cost Savings for Enterprises*. https://www.saturnme.com/how-proxmox-delivers-massive-cost-savings-for-enterprises/  
- JATIT. (2022). *Advancing Malware Artifact Detection and Analysis through Memory Forensics*. https://www.jatit.org/volumes/Vol102No4/21Vol102No4.pdf  
- ThinkMind. (2022). *Longitudinal Study of Persistence Vectors in Windows Malware*. https://www.thinkmind.org/articles/securware_2022_1_50_30018.pdf  
- Red Hat. (2024). *Ansible Automation Insights Datasheet*. https://www.redhat.com/en/resources/ansible-automation-insights-datasheet  
- Tamnoon. (2024). *Automated Cloud Remediation Guide*. https://tamnoon.io/blog/automated-cloud-remediation-guide/

---
