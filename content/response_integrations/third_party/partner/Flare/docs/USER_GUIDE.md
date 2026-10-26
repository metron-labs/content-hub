# Flare for Google SecOps — Installation and User Guide

This guide covers the Flare response integration: the existing connector configuration, the SOAR actions, and the example playbook.

## 1. Before you start

You need:

- A Flare API key with access to the tenant you want to query.
- The numeric Flare tenant ID. An API key can reach more than one tenant.
- A Google SecOps environment where this Content Hub integration is installed.

Create the API key in the Flare platform, then copy the tenant ID from the same account. The key is stored as a password parameter and is not written to action logs.

## 2. Configure the integration

Open the Flare integration instance and set:

| Parameter | Required | Notes |
| --- | --- | --- |
| Flare API Key | Yes | Sent only to Flare, to `POST /tokens/generate`. Actions never handle the token. |
| Flare Tenant ID | Yes | One ID, or several IDs separated by commas (for example `123,456`). |

Run **Ping** after saving. Ping checks the API key and every configured tenant.

### Several tenants

The connector can ingest all configured tenants. Each action runs against one tenant:

- If the instance has a single tenant ID, leave the action's **Tenant ID** empty.
- If the instance has several IDs, set **Tenant ID** on the action to one of those IDs. Any other value fails the action before a request is sent.

## 3. How actions behave

- Results are returned as JSON (`JsonResult`) for the next playbook step. List actions return `{"items": [...], "count": n}`.
- A missing record (HTTP 404) completes with result `false`. Authentication, permission, rate-limit, and validation errors fail the action.
- List actions accept **Max Records To Return** (1–1000, default 50). Search-style results page with a cursor. Identifier, alert, and entity lists page with `limit` and `offset`.
- Calls are paced to Flare's organization limits (4 requests/second for basic calls, 1 request/second for search). HTTP 429 is retried after the wait Flare recommends. HTTP 401 refreshes the token once.

Two actions change data in Flare: **Execute Event Action** and **Set Identifier Status**.

Endpoint paths follow the Flare Actions API list. Confirm them against the current Flare API reference before production use. Paths are defined in `core/constants.py`.

## 4. Actions

### Events

| Action | Method and path | Parameters |
| --- | --- | --- |
| Get Event Details | `GET /firework/v4/events/` | Event UID |
| Get Event Field Details | `GET /events/v2/expand` | Event UID, Field Path |
| Get Event AI Insights | `GET /events/ai-assistance` | Event UID |
| Execute Event Action | `POST /firework/v4/events/actions` | Action Type (`remediate`, `ignore`, `unignore`), Event UIDs (comma-separated, maximum 10) |
| Explain Identifier Match | `GET /events/explain-identifier` | Event UID, Identifier ID |

Execute Event Action sends `{"action": {"type": "..."}, "targets": [{"uid": "..."}]}`.

### Global search

| Action | Method and path | Parameters |
| --- | --- | --- |
| Search Global Data | `POST /global/_search` | Query, Categories, From Date, To Date, Max Records To Return |
| Get Global Search Quota | `GET /global/_search/quota` | None |

Dates are ISO 8601 (`2026-01-31T00:00:00Z`). **From Date** must be earlier than **To Date**. Each search uses Flare global search quota. The action logs a warning when it runs.

### Identifiers

| Action | Method and path | Parameters |
| --- | --- | --- |
| List Identifiers | `GET /firework/v4/identifiers/` | Type, Status, Max Records To Return |
| Get Identifier Details | `GET /firework/v4/identifiers/{identifier_id}` | Identifier ID |
| Set Identifier Status | `POST /firework/v4/identifiers/{identifier_id}/status` | Identifier ID, Enabled |

Set Identifier Status sends `{"enabled": true}` or `{"enabled": false}`.

### Alert rules

These are Flare alert rules, not Google SecOps alerts.

| Action | Method and path | Parameters |
| --- | --- | --- |
| List Alerts | `GET /firework/v4/alerts/` | Max Records To Return |
| Get Alert Details | `GET /firework/v4/alerts/{alert_id}` | Alert ID |
| List Alert Channels | `GET /firework/v4/alerts/channels` | Channel Type (optional) |

### Entities

| Action | Method and path | Parameters |
| --- | --- | --- |
| List Entities | `POST /entities/_list` | Entity Type, Query, Max Records To Return |
| Get Entity Details | `GET /entities/{entity_id}` | Entity ID |

List Entities sends the resolved tenant ID in the request body. There is no separate tenant parameter for the Flare API.

## 5. Example playbook

**Flare - Event Triage and Response** (`content/playbooks/third_party/partner/flare_event_triage`) is a reference playbook for cases created by the Flare connector. It does not run automatically. Attach it to Flare cases and run it, or turn on automatic execution after you confirm the scenario with Flare.

Steps:

1. **Get Event Details**, using `[Event.flare_uid]` from the connector event.
2. **Get Event AI Insights** for the same UID.
3. **Explain Identifier Match**, using the first identifier id from the event details JSON.
4. If `metadata.severity` is `high` or `critical`, **Execute Event Action** with `remediate`. Otherwise `ignore`.

Both last steps change the event in Flare. Adjust the identifier placeholder if your event payload uses a different field than `identifiers[].id`.

## 6. Troubleshooting

| Message | What to check |
| --- | --- |
| Invalid API Key | The Flare API Key on the integration instance. |
| Tenant ID is not configured | **Tenant ID** must be one of the IDs on the instance. |
| Several tenants | Set **Tenant ID** on the action. |
| Rate limit reached | Wait and run again. Pacing and retries already ran. |
| Not found, result false | The id is valid input but Flare has no matching record. |
