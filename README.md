# Support Example/Template Scripts

Example scripts/templates of potential interest for Endpoint Admins.

Scripts are minimally tested and meant for reference only, if using scripts from this repo please review prior to execution.


Scripts:
----------------
- Read_only_actions/Guest_collections/role_lister.sh
   - Return roles for Guest Collections on an Endpoint

- Read_only_actions/Guest_collections/acl_lister.sh
  - Return ACL's for Guest Collections on an Endpoint

- Read_only_actions/Guest_collections/acl_and_role.sh
  - Return ACL's and Role assignments for Guest Collections on an Endpoint

- Updating_scripts/collection_visibility_updater.sh
  - Update 'Visibility' state for all collections on a given Endpoint

- Updating_scripts/Endpoint_Migrater/endpoint_migrater.py
  - Migrate Storage-Gateways/Collections from a source Endpoint to the given Dest Endpoint
     - Initially copies collections set to 'private' to allow Admins to confirm ACL's, Roles and paths prior to turning over to end-users
     - Does not currently support copying Guest Collections based on cloud connectors
     - Will only copy from the source, no 'delete' actions are performed on either Src or Dest Endpoints
