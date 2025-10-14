# Support Example/Template Scripts

Example scripts/templates of potential interest for Endpoint Admins.

__Note: _Scripts are minimally tested and meant for reference only, if using scripts from this repo please review prior to execution.


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
        - Example Usage:
            ```
            ./endpoint_migrator.py \
	            --src-endpoint ec8b45ea-7c9a-4d62-b7ba-4f70c83acf7f \
	            --dst-endpoint cc4bab90-c464-4184-9ad6-a0219fc126dd \
	            --service-account-uuid 45af811c-4f4f-4d51-a0e6-0cfb192ee937 \
	            --service-account-secret ${secret_value} \
	            --src-endpoint-fqdn xda031.0ec8.data.globus.org \
	            --dst-endpoint-fqdn z2cbc9.bd7c.gaccess.io \
	            --local-svc-account james \
	            --identity-domain globus.org \
                --dst-collection-suffix " (HA)" \
                --ha \
                --skip-collections e2511f21-a08a-4f6d-b899-41773d7b121f,e3669d78-ad82-4ec1-85a2-2aa88af88d17,491ee7a0-a62f-4a2c-9189-ee7d3fe0000b  
            ```
