---
title: Mobile IPC commands
description: Generated Tauri command surface for Obsign and Brass Console.
---

> Generated from source for ezpds **v0.5.0**. Do not edit this page by hand.

These are the literal commands invoked by each frontend registry.

## Obsign identity wallet

Source: `apps/identity-wallet/src/lib/ipc/`

| Command | Kind |
| --- | --- |
| `arm_identity_leg` | App command |
| `authenticate_migration_source` | App command |
| `authenticate_source_pds` | App command |
| `build_did_web_migration_document_cmd` | App command |
| `build_migration_op_cmd` | App command |
| `build_recovery_override_cmd` | App command |
| `change_handle_cmd` | App command |
| `check_handle_resolution` | App command |
| `check_identity_status` | App command |
| `complete_did_web_ceremony` | App command |
| `complete_oauth_flow` | App command |
| `confirm_agent_claim` | App command |
| `confirm_identity_removal` | App command |
| `create_account` | App command |
| `create_destination_account` | App command |
| `detect_migration_path_cmd` | App command |
| `ensure_identity_session` | App command |
| `finalize_migration` | App command |
| `get_agent_audit` | App command |
| `get_appearance_preference` | App command |
| `get_available_user_domains` | App command |
| `get_device_key_id` | App command |
| `get_identity_handle_domains` | App command |
| `get_pds_url` | App command |
| `get_stored_did_doc` | App command |
| `list_agents` | App command |
| `list_identities` | App command |
| `perform_did_ceremony` | App command |
| `plugin:auth-session|start` | Tauri plugin |
| `plugin:sharesheet|share_text` | Tauri plugin |
| `prepare_did_web_ceremony` | App command |
| `prepare_migration` | App command |
| `preview_agent_claim` | App command |
| `refresh_did_doc` | App command |
| `register_created_identity` | App command |
| `register_handle` | App command |
| `request_claim_verification` | App command |
| `request_identity_removal` | App command |
| `resolve_identity` | App command |
| `revoke_agent` | App command |
| `save_pds_url` | App command |
| `set_appearance_preference` | App command |
| `sign_and_verify_claim` | App command |
| `sovereign_login` | App command |
| `submit_claim` | App command |
| `submit_did_web_migration_document_cmd` | App command |
| `submit_migration_op_cmd` | App command |
| `submit_recovery_override_cmd` | App command |
| `tombstone_identity` | App command |
| `transfer_blobs` | App command |
| `transfer_preferences` | App command |
| `transfer_repo` | App command |
| `verify_import` | App command |

## Brass Console

Source: `apps/admin-companion/src/lib/ipc.ts`

| Command | Kind |
| --- | --- |
| `biometric_enabled` | App command |
| `cancel_transfer` | App command |
| `generate_claim_code` | App command |
| `get_account_storage` | App command |
| `get_account_usage` | App command |
| `get_or_create_device_key` | App command |
| `get_server_health` | App command |
| `get_subject_status` | App command |
| `issue_reset_token` | App command |
| `list_accounts` | App command |
| `list_admin_devices` | App command |
| `list_claim_codes` | App command |
| `list_pairings` | App command |
| `list_transfers` | App command |
| `pair_device` | App command |
| `rename_pairing` | App command |
| `revoke_account_credentials` | App command |
| `revoke_admin_device` | App command |
| `revoke_claim_code` | App command |
| `revoke_self` | App command |
| `set_account_email` | App command |
| `set_active_pairing` | App command |
| `set_biometric_enabled` | App command |
| `unpair` | App command |
| `update_subject_status` | App command |
