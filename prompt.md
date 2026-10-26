Role: Senior SecOps Integration Engineer & Python Developer

Context:
I am expanding the existing Flare integration located at `/home/ankushyadav_metronl/work/content-hub/content/response_integrations/third_party/partner/Flare` in my Google SecOps repository. I need to add 15 new SOAR actions and reference playbooks based on:
1. Technical Scope Document: `/home/ankushyadav_metronl/work/content-hub/TS _ Flare __ Google SecOps Extension for SOAR Actions .md`
2. Action Endpoints List: `/home/ankushyadav_metronl/work/content-hub/Copy of Flare Actions - API List - 26th Oct_ Flare Actions API List.csv`
3. API Reference: https://api.docs.flare.io/api-reference/tokens/endpoints/generate

Task Objectives:
Analyze the provided context files and generate a comprehensive execution plan along with the core technical boilerplate code required to implement these actions into the Google SecOps application.

Please structure your output into the following sections:

1. System Architecture & File Structure Mapping
   - Map out the exact files to create/modify within `@content/response_integrations/third_party/partner/Flare/` (e.g., `definition.yaml`, `FlareManager.py`, individual `<action_name>.py` scripts, and `tests/test_actions/`).
   - Detail how API keys and pagination should be handled centrally within `FlareManager.py`.

2. Step-by-Step Implementation Guide
   - Show how to register the new actions in `definition.yaml` with correct inputs, outputs, parameters, and display names.
   - Provide a reusable Python boilerplate for one complete Action class utilizing `SiemplifyAction` / `tip-common` standards (including `add_result_json`, error handling, and output status).
   - Detail the mapping for the 15 actions specified in Section 3.2 of the technical scope (Events, Global Search, Identifiers, Alerts, Entities).

3. Testing & Validation Checklist
   - Outline unit tests to add under `tests/test_actions/` to verify endpoint parameter handling and mock responses.
   - List the required SOW deliverables (Test Plan matrix, User Guide updates, and Release Notes entries in `release_notes.yaml`).

Instructions:
- Keep responses concise, modular, and directly actionable.
- Rely on standard Google SecOps SDK conventions (`SiemplifyAction`, `SiemplifyUtils`).