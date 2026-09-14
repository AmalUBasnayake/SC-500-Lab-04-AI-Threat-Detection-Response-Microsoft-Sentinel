![Banner](Evidence/banner.png)

# 🛡️ SC-500 Lab 04 — AI Threat Detection & Response with Microsoft Sentinel

> Hands-on Microsoft SC-500 Cloud & AI Security Engineer lab demonstrating AI workload telemetry, detection engineering, KQL analytics, Microsoft Sentinel alerting, incident investigation, classification, and resolution.

![Azure](https://img.shields.io/badge/Microsoft%20Azure-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white)
![Microsoft Sentinel](https://img.shields.io/badge/Microsoft%20Sentinel-5E5CE6?style=for-the-badge&logo=microsoft&logoColor=white)
![Azure AI Foundry](https://img.shields.io/badge/Azure%20AI%20Foundry-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white)
![KQL](https://img.shields.io/badge/KQL-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)
![SC-500](https://img.shields.io/badge/SC--500-AI%20Security-blue?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1499.002-red?style=for-the-badge)

---

## 📌 Overview

This hands-on lab demonstrates how to build an **AI security monitoring, detection, investigation, and response workflow** using **Azure AI Foundry, Azure Monitor, Log Analytics, and Microsoft Sentinel**.

The objective was not simply to deploy an AI workload, but to implement an operational security capability capable of detecting abnormal AI model invocation activity and driving that activity through a complete **SOC incident lifecycle**.

### Security Workflow

[![Security Workflow](Architecture/security_workflow.png)](Architecture/security-workflow.png)

---

# 🎯 Lab Objectives

This lab was designed to demonstrate the ability to:

- Deploy a controlled Azure AI security lab environment
- Deploy and test an AI model workload
- Enable AI workload diagnostic telemetry
- Identify security-relevant AI metrics
- Ingest telemetry into Log Analytics
- Perform security analytics using KQL
- Engineer a Microsoft Sentinel detection rule
- Map the detection to MITRE ATT&CK
- Generate and validate a security alert
- Investigate the resulting Sentinel incident
- Classify the activity appropriately
- Document the investigation
- Resolve the incident using a SOC workflow
- Apply Azure cost-control principles

---

# 🏗️ Architecture

![SC-500 Lab 04 Architecture](Architecture/architecture-diagram.png)

## Architecture Components

| Component | Purpose |
|---|---|
| Azure AI Foundry | Hosts the controlled AI workload |
| GPT-5.6 Luna | AI model used for controlled telemetry generation |
| Azure Monitor | Provides platform metrics and monitoring |
| Log Analytics | Central telemetry analysis layer |
| Microsoft Sentinel | SIEM and security detection platform |
| KQL | Detection and investigation language |
| MITRE ATT&CK | Threat behavior classification |
| Sentinel Incident | Investigation and response workflow |

---

# ☁️ Azure Environment

| Resource | Configuration |
|---|---|
| Resource Group | `rg-sc500-ai-sec-lab` |
| Log Analytics | `law-sc500-ai-sec` |
| Azure AI Foundry | `foundry-sc500-ai-sec` |
| Foundry Project | `proj-sc500-ai-sec` |
| Region | East US |
| Model | GPT-5.6 Luna |
| Deployment Type | Global Standard |
| Sentinel | Enabled |
| Managed Identity | System-assigned |
| Inbound Networking | All networks |
| Outbound Networking | No Outbound Networking |
| Encryption | Microsoft-managed keys |

> **Cost-control note:** This lab intentionally avoided unnecessary supporting resources such as Application Insights, Storage Accounts, Event Hubs, private endpoints, and automation infrastructure. The objective was to demonstrate AI security monitoring while keeping the lab cost-conscious.

---

# 🔐 Security Design

## Identity

The Azure AI Foundry resource uses a **system-assigned managed identity**.

This avoids embedding long-lived credentials into applications and follows Azure identity best practices.

## Network Security

For this lab, inbound networking was intentionally left publicly accessible because the primary objective was **AI telemetry, detection engineering, and incident response**.

A separate Zero Trust / Private Endpoint lab covers private networking.

Outbound networking was configured as:

```text
No Outbound Networking
```

This reduces unnecessary external connectivity from the AI workload.

## Encryption

Microsoft-managed encryption keys were used.

Customer-managed keys were intentionally excluded because key management was outside the primary objective of this detection engineering lab.

---

# 🤖 AI Workload

A controlled Azure AI Foundry project was created and a GPT-5.6 Luna deployment was configured.

### Controlled Validation Prompt

```text
This is a controlled SC-500 security telemetry test.
Respond with: AI telemetry test successful.
```

Expected response:

```text
AI telemetry test successful.
```

This confirmed that the model deployment was operational before generating security telemetry.

## Evidence

[![Foundry Resource Deployed](Evidence/15-foundry-resource-deployed.png)](Evidence/15-foundry-resource-deployed.png)

*Figure 1: Azure AI Foundry resource successfully deployed.*

[![Foundry Project](Evidence/16-foundry-project-baseline.png)](Evidence/16-foundry-project-baseline.png)

*Figure 2: Azure AI Foundry project baseline.*

[![Model Deployment](Evidence/17-foundry-model-deployment-baseline.png)](Evidence/17-foundry-model-deployment-baseline.png)

*Figure 3: AI model deployment configuration.*

[![Model Details](Evidence/18-foundry-model-details-gpt56-luna.png)](Evidence/18-foundry-model-details-gpt56-luna.png)

*Figure 4: GPT-5.6 Luna model deployment details.*

[![Model Deployed](Evidence/20-foundry-gpt56-luna-deployed.png)](Evidence/20-foundry-gpt56-luna-deployed.png)

*Figure 5: GPT-5.6 Luna deployment successfully completed.*

[![Controlled AI Test](Evidence/25-foundry-controlled-ai-telemetry-test.png)](Evidence/25-foundry-controlled-ai-telemetry-test.png)

*Figure 6: Controlled AI telemetry test executed successfully.*


---

# 📊 AI Telemetry Collection

Diagnostic settings were configured to send relevant Foundry telemetry to the Log Analytics workspace.

Configured categories included:

- Audit Logs
- Request and Response Logs
- Azure OpenAI Request Usage
- AllMetrics

Destination:

```text
law-sc500-ai-sec
```

## Evidence

[![Diagnostic Settings Baseline](Evidence/21-foundry-diagnostic-settings-baseline.png)](Evidence/21-foundry-diagnostic-settings-baseline.png)

*Figure 7: Diagnostic settings baseline for the AI workload.*

[![Diagnostic Configuration](Evidence/22-foundry-diagnostic-setting-configuration.png)](Evidence/22-foundry-diagnostic-setting-configuration.png)

*Figure 8: Diagnostic categories configured for telemetry collection.*

[![Diagnostic Setting Enabled](Evidence/23-foundry-diagnostic-setting-enabled.png)](Evidence/23-foundry-diagnostic-setting-enabled.png)

*Figure 9: Diagnostic setting enabled and sending telemetry to Log Analytics.*


---

# 🔎 Telemetry Discovery

Initial investigation showed that request/response diagnostic events were available through:

```text
AzureDiagnostics
```

However, the available RequestResponse schema did not expose a reliable prompt/response content field suitable for this detection objective.

Instead of forcing content-based detection, the lab pivoted to **model invocation telemetry**.

This is an important detection-engineering decision:

> **Detection logic should be based on reliable telemetry fields rather than assuming that every AI request log contains usable prompt content.**

---

# 📈 ModelRequests Detection Signal

The following metric was identified as a useful security signal:

```text
ModelRequests
```

The metric represents model inference API request activity.

## Initial Validation Query

```kql
AzureMetrics
| where TimeGenerated > ago(24h)
| where Resource =~ "FOUNDRY-SC500-AI-SEC"
| where MetricName == "ModelRequests"
| project
    TimeGenerated,
    MetricName,
    Total,
    Count,
    Average,
    Minimum,
    Maximum,
    TimeGrain,
    UnitName,
    Resource
| order by TimeGenerated desc
```

## Evidence


![32 foundry ai metrics confirmed](Evidence/32-foundry-ai-metrics-confirmed.png)
![33 foundry modelrequests confirmed](Evidence/33-foundry-modelrequests-confirmed.png)
![34 foundry modelrequests aggregated](Evidence/34-foundry-modelrequests-aggregated.png)


---

# 🚨 Detection Engineering

## Detection Scenario

The detection objective was to identify a sudden increase in AI model invocation activity.

Potential security implications include:

- Automated request flooding
- Excessive model consumption
- Resource exhaustion
- Abuse of an AI endpoint
- Unexpected application behavior
- Potential denial-of-service style activity

---

# 🧠 Detection Logic

A five-minute aggregation window was selected.

Detection threshold:

```text
5 or more model requests within 5 minutes
```

## KQL Detection Query

```kql
AzureMetrics
| where TimeGenerated > ago(5m)
| where Resource =~ "FOUNDRY-SC500-AI-SEC"
| where MetricName == "ModelRequests"
| summarize
    RequestCount = sum(Total),
    PeakRequests = max(Maximum)
    by bin(TimeGenerated, 5m)
| where RequestCount >= 5
```

## Detection Rationale

The rule intentionally uses:

```text
Time Window + Request Volume
```

rather than individual request content.

This makes the detection useful even when request/response logging does not expose application-level prompt content.

## Evidence


![35 foundry modelrequests traffic spike](Evidence/35-foundry-modelrequests-traffic-spike.png) 
![36 ai model request spike detection query](Evidence/36-ai-model-request-spike-detection-query.png)


---

# 🛡️ Microsoft Sentinel Analytics Rule

## Rule Configuration

| Setting | Value |
|---|---|
| Rule Name | `AI Model Request Spike - SC500 Lab` |
| Rule Type | Scheduled Detection |
| Severity | Medium |
| Frequency | Every 5 minutes |
| Lookup Period | 5 minutes |
| Alert Threshold | Query results > 0 |
| Incident Creation | Enabled |
| Status | Enabled |
| MITRE Tactic | Impact |
| MITRE Technique | T1499 |
| MITRE Sub-technique | T1499.002 |

## Evidence


![37 sentinel ai request spike mitre mapping](Evidence/37-sentinel-ai-request-spike-mitre-mapping.png)
![38 sentinel ai request spike query scheduling](Evidence/38-sentinel-ai-request-spike-query-scheduling.png)
![39 sentinel incident settings](Evidence/39-sentinel-incident-settings.png)
![41 sentinel ai request spike rule review](Evidence/41-sentinel-ai-request-spike-rule-review.png)
![42 sentinel ai request spike rule enabled](Evidence/42-sentinel-ai-request-spike-rule-enabled.png)


---

# 🎯 MITRE ATT&CK Mapping

The detection was mapped to:

### Tactic

```text
Impact
```

### Technique

```text
T1499 — Endpoint Denial of Service
```

### Sub-technique

```text
T1499.002 — Service Exhaustion Flood
```

The mapping reflects the behavior being detected: repeated requests that could contribute to excessive service/resource consumption.

> **Important:** The MITRE mapping represents the behavior the analytic is designed to detect. It does not mean that the controlled lab activity itself was malicious.

---

# 💥 Controlled Security Test

Controlled model requests were generated to create a measurable request spike.

The detection query successfully identified:

```text
RequestCount = 8
PeakRequests = 1
```

within the detection window.

This demonstrated that the analytics rule could identify abnormal model invocation volume.

## Evidence


![43 sentinel ai request spike incident created](Evidence/43-sentinel-ai-request-spike-incident-created.png)
![46 sentinel alert query result 8 requests](Evidence/46-sentinel-alert-query-result-8-requests.png)
![47 sentinel alert exact kql query](Evidence/47-sentinel-alert-exact-kql-query.png)


---

# 🚨 Alert Generation

The Sentinel analytics rule generated:

```text
AI Model Request Spike - SC500 Lab
```

Alert severity:

```text
Medium
```

Detection source:

```text
Scheduled Detection
```

Service source:

```text
Microsoft Sentinel
```

The alert was successfully promoted into a Sentinel incident.

## Evidence


![43 sentinel ai request spike incident created](Evidence/43-sentinel-ai-request-spike-incident-created.png)
![45 sentinel alert details list](Evidence/45-sentinel-incident-alert-details-list.png)
![46 sentinel alert query result 8 requests](Evidence/46-sentinel-alert-query-result-8-requests.png)
![47 sentinel alert exact kql query](Evidence/47-sentinel-alert-exact-kql-query.png)


---

# 🔬 Incident Investigation

The resulting incident was:

```text
AI Model Request Spike - SC500 Lab
```

Investigation confirmed:

- The detection rule fired correctly
- Eight model requests were observed within the detection window
- The activity originated from the controlled lab test
- No malicious activity was identified
- No unauthorized access was identified
- No remediation was required

## Evidence


![44 sentinel incident investigation overview](Evidence/44-sentinel-incident-investigation-overview.png)
![45 sentinel alert details list](Evidence/45-sentinel-incident-alert-details-list.png)
![48 sentinel incident evidence response baseline](Evidence/48-sentinel-incident-evidence-response-baseline.png)
![49 sentinel incident summary](Evidence/49-sentinel-incident-summary.png)


---

# 🧾 Incident Classification

Because the activity was intentionally generated as part of a controlled security test, the incident was classified as:

```text
Benign Positive
```

This demonstrates an important SOC principle:

> A detection firing successfully does not automatically mean that the underlying activity is malicious.

Analysts must validate the context before determining whether an alert represents a true positive, false positive, or expected security activity.

## Evidence


![50 sentinel incident classified benign positive](Evidence/50-sentinel-incident-classified-benign-positive.png)


---

# 📝 Investigation Documentation

The following investigation conclusion was added to the incident:

```text
Controlled SC-500 AI telemetry test generated eight model requests
within the detection window. The Sentinel analytics rule correctly
detected the request spike. No malicious activity or unauthorized
access was identified. The incident was classified as expected
security test activity. No remediation was required.
```

## Evidence

[![Investigation Comment](Evidence/51-sentinel-incident-investigation-comment.png)]


*Figure 35: Investigation conclusion documented in the Sentinel incident.*

---

# ✅ Incident Resolution

The incident was subsequently resolved after investigation.

Final state:

```text
Status: Resolved
Severity: Medium
Classification: Benign Positive
Alerts: 1
Activities: 1
```

## Evidence

[![Incident Resolved](Evidence/52-sentinel-incident-resolved.png)](Evidence/52-sentinel-incident-resolved.png)

*Figure 36: Final Sentinel incident state showing resolution.*


---

# 🔄 Complete SOC Lifecycle

This lab demonstrates the following operational workflow:

```text
1. AI Workload Deployment
          ↓
2. Telemetry Generation
          ↓
3. Telemetry Ingestion
          ↓
4. Security Signal Identification
          ↓
5. KQL Detection Engineering
          ↓
6. Sentinel Analytics Rule
          ↓
7. Alert Generation
          ↓
8. Incident Creation
          ↓
9. Analyst Investigation
          ↓
10. Incident Classification
          ↓
11. Investigation Documentation
          ↓
12. Incident Resolution
```

---

# 🧪 Detection Validation

The detection was independently validated using:

```kql
AzureMetrics
| where TimeGenerated > ago(1h)
| where Resource =~ "FOUNDRY-SC500-AI-SEC"
| where MetricName == "ModelRequests"
| summarize
    RequestCount = sum(Total),
    PeakRequests = max(Maximum)
    by bin(TimeGenerated, 5m)
| where RequestCount >= 5
| order by TimeGenerated desc
```

Observed validation result:

```text
RequestCount: 11
PeakRequests: 1
```

A subsequent controlled test generated an incident with:

```text
RequestCount: 8
```

This provided both **telemetry validation** and **end-to-end detection validation**.

---

# 💰 Cost Optimization

This lab was designed with Azure Startup credit conservation in mind.

## Cost-Control Decisions

- Used a single Resource Group
- Used a single Log Analytics workspace
- Avoided unnecessary Application Insights
- Avoided Storage Account integration
- Avoided Event Hub integration
- Avoided private endpoint infrastructure because it was covered by a separate lab
- Used a serverless/global standard model deployment
- Used a lightweight request-volume detection
- Did not deploy unnecessary SOAR infrastructure
- Deleted the lab Resource Group after evidence collection

## Lifecycle Strategy

```text
Build
  ↓
Test
  ↓
Capture Evidence
  ↓
Document
  ↓
Delete Lab Resources
```

This prevents completed training environments from generating unnecessary ongoing costs.

---

# 🎓 SC-500 Relevance

This lab reinforces several SC-500 security engineering capabilities.

| SC-500 Area | Lab Implementation |
|---|---|
| AI Security | Azure AI Foundry security monitoring |
| Security Monitoring | Azure Monitor + Log Analytics |
| SIEM | Microsoft Sentinel |
| Detection Engineering | KQL analytics rule |
| Incident Response | Sentinel incident lifecycle |
| Threat Detection | Model request anomaly detection |
| Governance | Resource configuration and identity |
| Security Operations | Investigation and classification |
| MITRE ATT&CK | T1499.002 mapping |
| Cloud Security | Azure-native monitoring architecture |

---

# 💼 Engineer-Level Skills Demonstrated

This project demonstrates practical experience with:

- Azure AI security monitoring
- Microsoft Sentinel
- KQL
- Log Analytics
- Azure Monitor
- Detection engineering
- Security analytics
- AI workload telemetry
- Incident investigation
- SOC operations
- MITRE ATT&CK
- Alert triage
- Incident classification
- Incident lifecycle management
- Cloud security architecture
- Cost-aware security engineering

---

# 🧠 Key Engineering Lessons

## 1. Telemetry Quality Determines Detection Quality

A detection should be designed around telemetry that is consistently available and operationally useful.

## 2. Do Not Force Content-Based Detection

If prompt/response content is not reliably available, pivot to behavioral telemetry such as request volume, status codes, latency, or token consumption.

## 3. Detection ≠ Compromise

A successful detection only indicates that the defined condition occurred.

Analysts must investigate the context.

## 4. Context Matters in SOC Operations

The same request pattern could represent:

```text
Legitimate Workload
        OR
Security Testing
        OR
Application Malfunction
        OR
Abuse
        OR
Denial-of-Service Activity
```

Therefore, incident classification requires investigation.

## 5. Security Engineering Must Consider Cost

A production-quality security architecture must balance:

```text
Security
+
Visibility
+
Detection Quality
+
Operational Complexity
+
Cost
```

---

# 📂 Repository Structure

```text
SC-500-Lab-04-AI-Threat-Detection-Response-Microsoft-Sentinel/
│
├── README.md
├── LICENSE
│
├── Architecture/
│   ├── architecture-diagram.png
│   └── security-workflow.png
│
├── KQL/
│   └── model-request-spike-detection.kql
│
└── Evidence/
    ├── 01-log-analytics-workspace-created.png
    ├── 02-sentinel-workspace-selection.png
    ├── ...
    ├── 50-sentinel-incident-classified-benign-positive.png
    ├── 51-sentinel-incident-investigation-comment.png
    └── 52-sentinel-incident-resolved.png
```

> **Repository note:** The `docs/` directory is intentionally not included. SC-500 relevance and MITRE ATT&CK mapping are documented directly in this README, while the executable KQL is maintained in the `KQL/` directory.

---

# 📸 Evidence Index

The complete evidence set provides a visual record of the lab from environment creation through final incident resolution.

> **Evidence presentation:** Key screenshots are displayed in the relevant technical sections above as clickable thumbnails. The complete evidence set is available below as compact links.

| # | Evidence | File |
|---:|---|---|
| 01 | Log Analytics Workspace Created | [`01-log-analytics-workspace-created.png`](Evidence/01-log-analytics-workspace-created.png) |
| 02 | Sentinel Workspace Selection | [`02-sentinel-workspace-selection.png`](Evidence/02-sentinel-workspace-selection.png) |
| 03 | Microsoft Sentinel Enabled | [`03-microsoft-sentinel-enabled.png`](Evidence/03-microsoft-sentinel-enabled.png) |
| 04 | Sentinel Free Trial Activated | [`04-sentinel-free-trial-activated.png`](Evidence/04-sentinel-free-trial-activated.png) |
| 05 | Sentinel Overview Baseline | [`05-sentinel-overview-baseline.png`](Evidence/05-sentinel-overview-baseline.png) |
| 06 | AI Security Detection Rules Baseline | [`06-ai-security-detection-rules-baseline.png`](Evidence/06-ai-security-detection-rules-baseline.png) |
| 07 | Foundry Environment Baseline | [`07-foundry-environment-baseline.png`](Evidence/07-foundry-environment-baseline.png) |
| 08 | Foundry Resource Basics | [`08-foundry-resource-basics.png`](Evidence/08-foundry-resource-basics.png) |
| 09 | Foundry Inbound Networking Baseline | [`09-foundry-inbound-networking-baseline.png`](Evidence/09-foundry-inbound-networking-baseline.png) |
| 10 | Foundry Outbound Networking | [`10-foundry-outbound-networking.png`](Evidence/10-foundry-outbound-networking.png) |
| 11 | Foundry Managed Identity | [`11-foundry-managed-identity.png`](Evidence/11-foundry-managed-identity.png) |
| 12 | Foundry Data Encryption | [`12-foundry-data-encryption.png`](Evidence/12-foundry-data-encryption.png) |
| 13 | Foundry Resource Tags | [`13-foundry-resource-tags.png`](Evidence/13-foundry-resource-tags.png) |
| 14 | Foundry Resource Review | [`14-foundry-resource-review.png`](Evidence/14-foundry-resource-review.png) |
| 15 | Foundry Resource Deployed | [`15-foundry-resource-deployed.png`](Evidence/15-foundry-resource-deployed.png) |
| 16 | Foundry Project Baseline | [`16-foundry-project-baseline.png`](Evidence/16-foundry-project-baseline.png) |
| 17 | Foundry Model Deployment Baseline | [`17-foundry-model-deployment-baseline.png`](Evidence/17-foundry-model-deployment-baseline.png) |
| 18 | Foundry Model Details — GPT-5.6 Luna | [`18-foundry-model-details-gpt56-luna.png`](Evidence/18-foundry-model-details-gpt56-luna.png) |
| 19 | GPT-5.6 Luna Deployment Settings | [`19-foundry-gpt56-luna-deployment-settings.png`](Evidence/19-foundry-gpt56-luna-deployment-settings.png) |
| 20 | GPT-5.6 Luna Deployed | [`20-foundry-gpt56-luna-deployed.png`](Evidence/20-foundry-gpt56-luna-deployed.png) |
| 21 | Foundry Diagnostic Settings Baseline | [`21-foundry-diagnostic-settings-baseline.png`](Evidence/21-foundry-diagnostic-settings-baseline.png) |
| 22 | Foundry Diagnostic Setting Configuration | [`22-foundry-diagnostic-setting-configuration.png`](Evidence/22-foundry-diagnostic-setting-configuration.png) |
| 23 | Foundry Diagnostic Setting Enabled | [`23-foundry-diagnostic-setting-enabled.png`](Evidence/23-foundry-diagnostic-setting-enabled.png) |
| 24 | Log Analytics Pre-Traffic Baseline | [`24-log-analytics-pre-traffic-baseline.png`](Evidence/24-log-analytics-pre-traffic-baseline.png) |
| 25 | Controlled AI Telemetry Test | [`25-foundry-controlled-ai-telemetry-test.png`](Evidence/25-foundry-controlled-ai-telemetry-test.png) |
| 26 | Request/Response Telemetry Confirmed | [`26-foundry-requestresponse-telemetry-confirmed.png`](Evidence/26-foundry-requestresponse-telemetry-confirmed.png) |
| 27 | Request/Response Events Confirmed | [`27-foundry-requestresponse-events-confirmed.png`](Evidence/27-foundry-requestresponse-events-confirmed.png) |
| 28 | Request/Response Schema Discovered | [`28-foundry-requestresponse-schema-discovered.png`](Evidence/28-foundry-requestresponse-schema-discovered.png) |
| 29 | AI Telemetry Security Fields | [`29-foundry-ai-telemetry-security-fields.png`](Evidence/29-foundry-ai-telemetry-security-fields.png) |
| 30 | Request/Response Evals Availability | [`30-foundry-requestresponse-evals-availability.png`](Evidence/30-foundry-requestresponse-evals-availability.png) |
| 31 | Request/Response Operation Baseline | [`31-foundry-requestresponse-operation-baseline.png`](Evidence/31-foundry-requestresponse-operation-baseline.png) |
| 32 | AI Metrics Confirmed | [`32-foundry-ai-metrics-confirmed.png`](Evidence/32-foundry-ai-metrics-confirmed.png) |
| 33 | ModelRequests Confirmed | [`33-foundry-modelrequests-confirmed.png`](Evidence/33-foundry-modelrequests-confirmed.png) |
| 34 | ModelRequests Aggregated | [`34-foundry-modelrequests-aggregated.png`](Evidence/34-foundry-modelrequests-aggregated.png) |
| 35 | ModelRequests Traffic Spike | [`35-foundry-modelrequests-traffic-spike.png`](Evidence/35-foundry-modelrequests-traffic-spike.png) |
| 36 | AI Model Request Spike Detection Query | [`36-ai-model-request-spike-detection-query.png`](Evidence/36-ai-model-request-spike-detection-query.png) |
| 37 | Sentinel AI Request Spike MITRE Mapping | [`37-sentinel-ai-request-spike-mitre-mapping.png`](Evidence/37-sentinel-ai-request-spike-mitre-mapping.png) |
| 38 | Sentinel AI Request Spike Query Scheduling | [`38-sentinel-ai-request-spike-query-scheduling.png`](Evidence/38-sentinel-ai-request-spike-query-scheduling.png) |
| 39 | Sentinel Incident Settings | [`39-sentinel-incident-settings.png`](Evidence/39-sentinel-incident-settings.png) |
| 40 | Sentinel Automated Response Baseline | [`40-sentinel-automated-response-baseline.png`](Evidence/40-sentinel-automated-response-baseline.png) |
| 41 | Sentinel AI Request Spike Rule Review | [`41-sentinel-ai-request-spike-rule-review.png`](Evidence/41-sentinel-ai-request-spike-rule-review.png) |
| 42 | Sentinel AI Request Spike Rule Enabled | [`42-sentinel-ai-request-spike-rule-enabled.png`](Evidence/42-sentinel-ai-request-spike-rule-enabled.png) |
| 43 | Sentinel AI Request Spike Incident Created | [`43-sentinel-ai-request-spike-incident-created.png`](Evidence/43-sentinel-ai-request-spike-incident-created.png) |
| 44 | Sentinel Incident Investigation Overview | [`44-sentinel-incident-investigation-overview.png`](Evidence/44-sentinel-incident-investigation-overview.png) |
| 45 | Sentinel Alert Details List | [`45-sentinel-alert-details-list.png`](Evidence/45-sentinel-alert-details-list.png) |
| 46 | Sentinel Alert Query Result — 8 Requests | [`46-sentinel-alert-query-result-8-requests.png`](Evidence/46-sentinel-alert-query-result-8-requests.png) |
| 47 | Sentinel Alert Exact KQL Query | [`47-sentinel-alert-exact-kql-query.png`](Evidence/47-sentinel-alert-exact-kql-query.png) |
| 48 | Sentinel Incident Evidence / Response Baseline | [`48-sentinel-incident-evidence-response-baseline.png`](Evidence/48-sentinel-incident-evidence-response-baseline.png) |
| 49 | Sentinel Incident Summary | [`49-sentinel-incident-summary.png`](Evidence/49-sentinel-incident-summary.png) |
| 50 | Sentinel Incident Classified Benign Positive | [`50-sentinel-incident-classified-benign-positive.png`](Evidence/50-sentinel-incident-classified-benign-positive.png) |
| 51 | Sentinel Incident Investigation Comment | [`51-sentinel-incident-investigation-comment.png`](Evidence/51-sentinel-incident-investigation-comment.png) |
| 52 | Sentinel Incident Resolved | [`52-sentinel-incident-resolved.png`](Evidence/52-sentinel-incident-resolved.png) |

> **Security note:** Before publishing evidence publicly, review screenshots to ensure subscription IDs, tenant identifiers, email addresses, account information, tokens, keys, URLs containing sensitive identifiers, and other sensitive metadata are not exposed.

---
# 🏁 Final Outcome

The lab successfully demonstrated an end-to-end **AI Security Detection & Response pipeline** using Microsoft Azure and Microsoft Sentinel.

The final validated workflow was:

[![Final Outcome](Architecture/final_outcome.png)](Architecture/final_outcome.png)

```text
AI Model Request
      ↓
Telemetry
      ↓
Log Analytics
      ↓
KQL Detection
      ↓
Sentinel Analytics Rule
      ↓
Alert
      ↓
Incident
      ↓
Investigation
      ↓
Classification
      ↓
Resolution
```

## Final Result

| Capability | Result |
|---|---|
| AI Workload | ✅ Deployed |
| Telemetry | ✅ Generated |
| Log Analytics Ingestion | ✅ Validated |
| KQL Detection | ✅ Successful |
| Sentinel Analytics Rule | ✅ Enabled |
| Alert | ✅ Generated |
| Incident | ✅ Created |
| Investigation | ✅ Completed |
| Classification | ✅ Benign Positive |
| Investigation Documentation | ✅ Completed |
| Resolution | ✅ Completed |

---

# 🚀 Future Enhancements

Potential production enhancements include:

- AI prompt-injection detection correlation
- Token-consumption anomaly detection
- HTTP 4xx/5xx anomaly detection
- Identity-based correlation with Microsoft Entra ID
- User/application/entity enrichment
- Microsoft Defender XDR correlation
- Automated Sentinel playbooks
- Threat intelligence enrichment
- UEBA-based anomaly detection
- Risk-based alert prioritization

These enhancements were intentionally excluded from the core lab to maintain a focused, cost-efficient detection engineering implementation.

---

# 👨‍💻 Author

**Amal Udayanga Basnayake**

Cybersecurity Engineer | Azure Security | SIEM & Threat Detection | Microsoft Security

### 🔗 Profiles

- GitHub: https://github.com/AmalUBasnayake
- Portfolio: https://amalcyberlab.vercel.app
- LinkedIn: https://linkedin.com/in/amal-udayanga-basnayake
- Medium: https://medium.com/@amalubasnayake

---

# ⭐ Project Classification

```text
Project Type:
Cloud Security / AI Security / SIEM / Detection Engineering

Platform:
Microsoft Azure

Security Platform:
Microsoft Sentinel

Query Language:
KQL

AI Platform:
Azure AI Foundry

Framework:
MITRE ATT&CK

Certification Alignment:
Microsoft SC-500
```

---

> **Built as part of the SC-500 Cloud & AI Security Engineer Master Class — hands-on security engineering portfolio.**
