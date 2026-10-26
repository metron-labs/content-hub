Scope    \|   Flare \<\> Google SecOps App Extension for  
SOAR Actions

[**1\. Overview	2**](#overview)

[**2\. Objectives	2**](#objectives)

[2.1 Introduction	2](#introduction)

[2.2 Motivation	2](#motivation)

[2.3 Requirement for Google SecOps Response Integration	3](#requirement-for-google-secops-response-integration)

[2.4 Architecture	3](#architecture)

[2.5 Technical stack	4](#technical-stack)

[2.6 Deliverables and Outcomes	4](#deliverables-and-outcomes)

[**3\. Scope of Work	5**](#scope-of-work)

[3.1 Application Configuration	5](#application-configuration)

[3.2 Flare Actions	5](#flare-actions)

[3.3 Common Action Capabilities	7](#common-action-capabilities)

[3.4 Example Playbooks	7](#example-playbooks)

[3.5 Application Packaging and Publication	8](#application-packaging-and-publication)

[**4\. Timelines and Phases	8**](#timelines-and-phases)

# 

1. # Overview {#overview}

This document describes the scope of work for a Flare Google SecOps Content Hub integration extension for the including the SOAR Actions. This document references the following Statement of Work (SOW)

| ![No type][image1] Item | ![No type][image1] Details |
| :---- | :---- |
| File Title | Metron SOW \| Flare-Secops Integrations |
| File Name | Metron SOW \- Flare \- Secops Integration.pdf |
| Docusign Envelope ID | 76F05717-69A2-43E6-A69F-7DE011729138 |

This scope defines the integration objectives, architectural approach, deliverables, estimated timelines, and commercial terms referenced to this SOW. All terms, conditions, and obligations stated herein are subject to and governed by the overarching SOW agreement executed on 31 Jan 2026 between the parties.

2. # Objectives {#objectives}

1. ## Introduction {#introduction}

[Flare](https://flare.io/) provides an AI-driven Continuous Threat Exposure Management (CTEM) platform that continuously scans the clear, deep, and dark web to proactively identify, prioritize, and remediate external cyber threats and digital exposures.

[Google Security Operations (SecOps)](https://cloud.google.com/security/products/security-operations) is a cloud-native platform by Google Cloud that unifies SIEM (Security Information and Event Management), SOAR (Security Orchestration, Automation, and Response), and Google Threat Intelligence into a single system built on Google’s core infrastructure.  
Metron has already completed and delivered an integration between Flare and Google SecOps that addresses the following use case:

* Connector: Ingest the Flare events into Google SecOps to create a case for each of the events detected by Flare.

The current SOW discusses the requirements for implementing the SOAR Actions that can be utilized to fetch more data from Flare while executing the playbooks in the Google SecOps.

2. ## Motivation {#motivation}

The high-level goals of this Integration that guide the design and implementation priorities are:

1. Extending Google Security Operations Flare application for additional SOAR Actions.  
2. Design, implement and publish the Flare app within the Google Security Operations [Content Hub](https://docs.cloud.google.com/chronicle/docs/secops/content_hub).  
3. Accelerate deployment for customers and provide a centralized interface for Threat Exposure management.

3. ## Requirement for Google SecOps Response Integration {#requirement-for-google-secops-response-integration}

The originally communicated requirements from the Flare team to Metron are:

1. **Connector** (*Already developed in previous SOW*) \- Pick up the alerts that are associated in your platform with Connectors \- you're pulling alerts in our SOAR platform. This will pick it up and put it in our SOAR CASE bucket of cases.  
2.  **Actions** \- IOC enrichment, E.g. Get Alert Details, any action that we could use from the platform that we can use in our Playbooks.  
3.  **Actions** \- items that are being used in playbooks in automated way or you can use it manually as well

Reference to the communication: [Link to the Slack message from Craig Dakin](https://metron-security.slack.com/archives/C0AL24EAMDX/p1792085971680369?thread_ts=1792079286.827779&cid=C0AL24EAMDX)

4. ## Architecture {#architecture}

# 

Here's a step-by-step description of the application workflow:

1. **Google SecOps Content Hub:** The Flare application will be published in the Google SecOps Content Hub, enabling customers to discover and install the integration into their Google SecOps environment. Once installed, the application will provide configuration options, SOAR actions, and example playbooks. These capabilities will allow customers to incorporate Flare threat intelligence into their existing security investigation and response workflows.  
2. **Application Configuration:** The Application Configuration module will allow customers to configure the connection between Google SecOps and the Flare platform. It will securely store the authentication credentials and connection settings required to communicate with Flare's public APIs. The configuration will also support connection validation to ensure successful communication with the Flare platform.  
3. **Flare Actions:** The integration will provide a set of SOAR actions that interact with Flare's public APIs to retrieve threat intelligence and exposure information. Each action will serve as a wrapper around the corresponding Flare API endpoint, allowing analysts to execute it manually or through automated playbooks. These actions will enable investigation, enrichment, and response workflows within Google SecOps.  
4. **Example Playbooks:** The application will include example playbooks demonstrating how Flare actions can be used for security investigation and remediation workflows. These playbooks can be triggered automatically based on incoming alerts, case conditions, or manually by security analysts. Customers can use the playbooks as provided or customize them according to their operational requirements.

5. ## Technical stack {#technical-stack}

Metron will use Python for implementing the actions and the Google Playbooks editor tools to develop the playbook. This is the default technical stack for Google SecOps applications.

6. ## Deliverables and Outcomes {#deliverables-and-outcomes}

For any feature, we will have the following deliverables

| ![No type][image2] Deliverable | ![No type][image3] Format | ![No type][image2] Notes |
| :---- | :---- | :---- |
| Source Code | GitHub Pull Request | This is the full source code for the feature, which should match all code quality and linting checks from the Flare engineering team. Two approvals are required on the Pull Request in order to consider it complete. |
| Test Plan | XLS | This is a test plan document which will contain all the test cases |
| Installation and User Guide | Markdown \+ PDF | A comprehensive installation and user guide that shows how to set up and use the integration. |
| Demo Video and Screenshots | MP4 \+ PNG | These should show the complete integration working end-to-end. Includes video details on how to set up credentials on the third party platform. |

3. # Scope of Work {#scope-of-work}

Metron will extend the existing Flare application for Google Security Operations (SecOps) by implementing SOAR actions and example playbooks to support automated threat investigation, enrichment, and response workflows.

The application will include the following components.

1. ## Application Configuration {#application-configuration}

The Application Configuration module will enable customers to establish and manage connectivity between Google SecOps and the Flare platform.

* Provide configuration fields for Flare API authentication and connection settings.  
* Securely store and manage API credentials using Google SecOps-supported mechanisms.  
* Implement connection validation to verify authentication and API accessibility.  
* Provide error handling and diagnostic messages for connection failures.

**Note:** This is already covered in the existing connector app. We can use the same application configuration. We just need to test this for the actions and playbooks.

2. ## Flare Actions {#flare-actions}

Metron will implement SOAR actions that serve as wrappers around Flare's public APIs. These actions will enable security analysts to retrieve threat intelligence, investigate exposures, and execute supported response operations directly from Google SecOps.

Each action will support the required input parameters, process API responses, and return structured results that can be consumed by subsequent playbook steps. Actions will support both manual execution and automated execution through Google SecOps playbooks.

The following actions are proposed for implementation, subject to final review and confirmation of API capabilities by the Flare team.

| \# | API Category | Action Name | Method | API Endpoint | Description |
| ----- | ----- | ----- | ----- | ----- | ----- |
| 1 | Events | Get Event Details | GET | `/events` (or V2) | Retrieve detailed metadata and threat context for a specific Flare event. |
| 2 | Events | Get Event Field Details | GET | `/events/v2/expand` | Retrieve expanded fields and nested event information. |
| 3 | Events | Get Event AI Insights | GET | `/events/ai-assistance` | Retrieve AI-generated event analysis, summaries, and remediation recommendations. |
| 4 | Events | Execute Event Action | POST | `/firework/v4/events/actions` | Perform event operations such as remediate, ignore, or unignore. |
| 5 | Events | Explain Identifier Match | GET | `/events/explain-identifier` | Explain why an event matched a monitored identifier. |
| 6 | Global Search | Search Global Data | POST | `/global/_search` | Search Flare's threat intelligence dataset across supported sources. |
| 7 | Global Search | Get Global Search Quota | GET | `/global/_search/quota` | Retrieve available search credits, quota limits, and usage. |
| 8 | Management – Identifiers | List Identifiers | GET | `/firework/v4/identifiers/` | List monitored assets and identifiers with filtering options. |
| 9 | Management – Identifiers | Get Identifier Details | GET | `/firework/v4/identifiers/{identifier_id}` | Retrieve identifier metadata, configuration, and monitoring scope. |
| 10 | Management – Identifiers | Set Identifier Status | POST | `/firework/v4/identifiers/{identifier_id}/status` | Enable or disable monitoring for a specific identifier. |
| 11 | Management – Alerts | List Alerts | GET | `/firework/v4/alerts/` | Retrieve configured Flare alert rules. |
| 12 | Management – Alerts | Get Alert Details | GET | `/firework/v4/alerts/{alert_id}` | Retrieve alert rule configuration, filters, and notification settings. |
| 13 | Management – Alerts | List Alert Channels | GET | `/firework/v4/alerts/channels` | Retrieve configured notification channels and destinations. |
| 14 | Entities | List Entities | POST | `/entities/_list` | Search threat entities such as threat actors, malware, and ransomware groups. |
| 15 | Entities | Get Entity Details | GET | `/entities/{entity_id}` | Retrieve threat entity profiles, risk levels, aliases, and contextual intelligence. |

3. ## Common Action Capabilities {#common-action-capabilities}

The following capabilities will be implemented across the applicable actions:

* Support required and optional API input parameters.  
* Process API responses and provide structured outputs.  
* Support pagination and filtering where applicable.  
* Handle authentication failures, API errors, and rate limits.  
* Provide execution logs and meaningful error messages.  
* Make action outputs accessible to subsequent playbook steps.  
* Support manual execution and automated playbook execution.

4. ## Example Playbooks {#example-playbooks}

Metron will develop 1 example playbooks demonstrating how Flare actions can be used for threat investigation, enrichment, or response within Google SecOps. Metron will work together with the Flare team to finalise the example scenario that should be delivered.

This playbook is a simple playbook that will serve as reference implementations only. Customers can use them as provided or customize the workflows, conditions, and response operations according to their security processes.

5. ## Application Packaging and Publication {#application-packaging-and-publication}

Metron will package the Flare application with its configuration module, supported SOAR actions, and example playbooks for distribution through the Google SecOps Content Hub.

The scope includes:

* Preparing the application package in accordance with Google SecOps content requirements.  
* Performing functional validation of the implemented actions and example playbooks.  
* Preparing the necessary configuration and usage documentation.  
* Submitting the updated application for publication in the Google SecOps Content Hub.  
* Addressing applicable review feedback associated with the implemented scope.

Publication will remain subject to Google's review and approval process.

4. # Timelines and Phases {#timelines-and-phases}

| Milestone | Description | Owner | Due Date |
| ----- | :---- | :---- | :---- |
| M-1 | Kick-off  | Metron | T \+ 0 wk |
| M-2 | Implement all 15 actions and 1 Playbook | Metron | T \+ 1 wk |
| M-3 | Test Plan & Integration Testing | Metron | T \+ 2 wk |
| M-4 | Documentation and Demo Video | Metron | T \+ 2 wk |
| M-5 | UAT handover | Metron | T \+ 2 wk |
| *Integration submitted to Flare for UAT* |  |  |  |
| Acceptance | UAT approval/sign-off | Flare | T \+ 4 wk |
| Publishing | Publish to marketplace | Metron | T \+ 4 wk |

T \= 22th October 2026  
Dates are adjustable by mutual written agreement.

[image1]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABQAAAAQAQMAAAAs1s1YAAAABlBMVEUAAABER0byc6G0AAAAAXRSTlMAQObYZgAAAB9JREFUeF5jYEAD9h8YmEA0MwOYZmSWWQjhs4H56BgAT4ECDeGaeV4AAAAASUVORK5CYII=>

[image2]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABQAAAAQAQMAAAAs1s1YAAAABlBMVEUAAABER0byc6G0AAAAAXRSTlMAQObYZgAAAB9JREFUeF5jYEAD9h8YmEA0MwOYZmSWWQjhs4H56BgAT4ECDeGaeV4AAAAASUVORK5CYII=>

[image3]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABQAAAAQAQMAAAAs1s1YAAAABlBMVEUAAABER0byc6G0AAAAAXRSTlMAQObYZgAAAB9JREFUeF5jYEAD9h8YmEA0MwOYZmSWWQjhs4H56BgAT4ECDeGaeV4AAAAASUVORK5CYII=>