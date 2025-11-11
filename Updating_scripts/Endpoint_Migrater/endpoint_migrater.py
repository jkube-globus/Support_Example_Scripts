import argparse
import datetime
from globus_sdk import scopes
import globus_sdk
import logging
import os
import re
import sys
import time

migrater_version = "0.0.4b"
src_storage_gateways = []
src_mapped_collections = []
src_guest_collections = []
storage_gateways_created = []
storage_gateway_creation_errors = []
collections_created = []
collection_creation_errors = []
non_existant_paths = []
dynamic_paths = []
collection_mapping = []
collections_to_skip = []

logFile = f"endpoint_migrater.{datetime.date.today()}.log"
logger = logging.getLogger(__name__)

# Create a formatter to define the log format
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# Create a file handler to write logs to a file
file_handler = logging.FileHandler(logFile)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)

# Create a stream handler to print logs to the console
formatter = logging.Formatter('%(message)s')
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(formatter)

# Add the handlers to the logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# Resetting our logger to make sure we get DEBUG+ logs
logger.setLevel(logging.DEBUG)


def get_scopes(Globus_SA_CLIENT_ID, Globus_SA_CLIENT_SECRET,
               ENDPOINT_UUID, MAPPED_COLLECTION_ID=None, high_assurance=False):

    # Use the Globus SDK ScopeBuilder to create our scope string
    TRANSFER_SCOPES = scopes.TransferScopes.all
    SRC_EP_SCOPES = scopes.GCSEndpointScopeBuilder(ENDPOINT_UUID).make_mutable(
            "manage_collections")
    if MAPPED_COLLECTION_ID and not high_assurance:
        logger.debug("We're requesting a `data_access` scope")
        SRC_EP_SCOPES.add_dependency(
            scopes.GCSCollectionScopeBuilder(MAPPED_COLLECTION_ID).data_access)
    elif MAPPED_COLLECTION_ID and high_assurance:
        logger.debug("We're NOT requesting a `data_access` scope")
        SRC_EP_SCOPES.add_dependency(
            scopes.GCSCollectionScopeBuilder(MAPPED_COLLECTION_ID))
    SRC_EP_SCOPES.add_dependency(
            TRANSFER_SCOPES)

    # The authorizer manages our access token for the scopes we request
    gcs_authorizer = globus_sdk.ClientCredentialsAuthorizer(
        # The ConfidentialAppAuthClient authenticates us to Globus Auth
        globus_sdk.ConfidentialAppAuthClient(
            Globus_SA_CLIENT_ID,
            Globus_SA_CLIENT_SECRET
        ),
        SRC_EP_SCOPES
    )
    return gcs_authorizer


def get_gcs_client(GCS_MANAGER_DOMAIN_NAME, gcs_authorizer):
    """
    Create a GCS Client so we can make API calls to
    the Source GCS Endpoints API
    """

    GCS_Client = globus_sdk.GCSClient(
            gcs_address=GCS_MANAGER_DOMAIN_NAME,
            authorizer=gcs_authorizer)
    return GCS_Client


def get_storage_gateway_details(GCS_CLIENT, SG_MARKER=None):

    if SG_MARKER is None:
        storage_gateway_response = GCS_CLIENT.get_storage_gateway_list(
            include='private_policies')
    else:
        storage_gateway_response = GCS_CLIENT.get_storage_gateway_list(
            include='private_policies',
            marker=SG_MARKER)

    return storage_gateway_response


def create_storage_gateway(
        XFER_Client,
        identity_Domain,
        DEST_GCS_MANAGER_DOMAIN_NAME,
        DEST_ENDPOINT_ID,
        SERVICE_USER,
        DEST_GCS_CLIENT,
        SRC_GCS_CLIENT,
        storage_gateway_dict,
        Globus_SA_CLIENT_ID,
        Globus_SA_CLIENT_SECRET,
        DEST_COLL_SUFFIX="",
        collections_to_skip=collections_to_skip,
        verbose=False,
        debug=False,
        public=False,
        high_assurance=False,
        no_high_assurance=False,
        force=False,
        dry_run=False):

    """
    Create a storage gateway on our destination endpoint
    """
    if dry_run:
        logger.info("===================================================")
        logger.info("\tDRY RUN")
        logger.info("===================================================")

    if debug:
        logger.debug(
                f"\n\nEquivalent to source SG: {storage_gateway_dict}")
        logger.debug("Variable values:")
        logger.debug(XFER_Client)
        logger.debug(identity_Domain)
        logger.debug(DEST_GCS_MANAGER_DOMAIN_NAME)
        logger.debug(DEST_ENDPOINT_ID)
        logger.debug(SERVICE_USER)
        logger.debug(DEST_GCS_CLIENT)
        logger.debug(SRC_GCS_CLIENT)
        logger.debug(storage_gateway_dict)
        logger.debug(Globus_SA_CLIENT_ID)
        if verbose:
            logger.critical(Globus_SA_CLIENT_SECRET)
        logger.debug(DEST_COLL_SUFFIX)
        logger.debug(collections_to_skip)
        logger.debug(verbose)
        logger.debug(debug)
        logger.debug(public)
        logger.debug(high_assurance)
        logger.debug(no_high_assurance)
    # storage_gateway_details = []
    GLOBUS_SA = f"{Globus_SA_CLIENT_ID}@clients.auth.globus.org"
    for sg in storage_gateway_dict["data"]:
        # If an Intra Endpoint copy, update SG display_name to avoid conflict
        if SRC_GCS_CLIENT == DEST_GCS_CLIENT:
            sg["display_name"] = sg["display_name"] + DEST_COLL_SUFFIX
        if debug:
            logger.info("Here's our SG:")
            logger.info(sg)
        if not sg.get("identity_mappings"):
            sg["identity_mappings"] = [
                    {"DATA_TYPE": "expression_identity_mapping#1.0.0",
                     "mappings": [{"match": "(.*)@"+identity_Domain,
                                   "output": "{0}", "source": "{username}"},
                                  {
                                   "match": GLOBUS_SA,
                                   "output": SERVICE_USER,
                                   "source": "{username}"
                                   }]}]
        else:
            sg["identity_mappings"][0]["mappings"].append(
                                  {
                                   "match": GLOBUS_SA,
                                   "output": SERVICE_USER,
                                   "source": "{username}"
                                   }
                    )
        if not sg.get("users_allow"):
            sg["users_allow"] = None

        if not sg.get("users_deny"):
            sg["users_deny"] = None

        if high_assurance and sg["high_assurance"] is not True:
            sg["high_assurance"] = True
        elif no_high_assurance and sg["high_assurance"] is True:
            sg["high_assurance"] = False
        elif sg["high_assurance"]:
            high_assurance = True
        else:
            high_assurance = False

        # Addressing a SDK typo
        if sg.get("allow_domains"):
            sg["allowed_domains"] = sg["allow_domains"]
            del sg["allow_domains"]

        # Adding clients.auth.globus.org to the storage-gateways to allow
        # Globus SA to create Guest Collections
        sg["allowed_domains"].append("clients.auth.globus.org")

        logger.info(f"\n\tCreating new destination SG - Equiv: {sg['id']}")
        logger.info(f"\t{'-'*73}")
        if dry_run:
            storage_gateways_created.append(
                    {sg["id"]: "DRY_RUN"})
        else:
            # Create dest storage-gateways
            try:
                DEST_SG_DETAILS = DEST_GCS_CLIENT.create_storage_gateway(sg)
                storage_gateways_created.append(
                        {sg["id"]: DEST_SG_DETAILS["id"]})
            except globus_sdk.GlobusAPIError as e:
                errors = []
                if e.errors:
                    if verbose or debug:
                        logger.error("sub-errors encountered")
                        logger.error("(code, message)")
                    for suberror in e.errors:
                        if verbose or debug:
                            logger.critical(suberror.code,
                                            suberror.message)
                        errors.append([suberror.code, suberror.message])
                    storage_gateway_creation_errors.append({sg["id"]: errors})

                counter = len("Display Name: " + sg["display_name"])
                counter2 = len("UUID - " + sg["id"])
                if counter2 > counter:
                    counter = counter2

                # DisplayName spacing
                dnCounter = len(f"Display Name: {sg['display_name']}")
                dnCounter = counter - dnCounter

                # UUID spacing
                uuidCounter = len(f"UUID - {sg['id']}")
                uuidCounter = counter - uuidCounter

                if not force:
                    banner = "Failed to create storage-gateway:"
                    # DisplayName spacing
                    bannerCounter = len(banner)
                    bannerCounter = counter - bannerCounter

                    logger.error(f"""
                     \n\n
                     !!{'!'*counter}!
                     ! {banner + ' '*bannerCounter}!
                     ! UUID - {sg["id"]}!
                     ! Display Name: {sg["display_name"] + ' '*dnCounter}!
                     ! UUID - {sg["id"] + ' '*uuidCounter}!
                     !!{'!'*counter}!
                     \n\n
                     """)
                    return 3
                else:
                    dest_storage_gateways = get_storage_gateway_details(
                            DEST_GCS_CLIENT)
                    for dest_sg in dest_storage_gateways['data']:
                        if dest_sg['display_name'] == sg['display_name']:
                            DEST_SG_DETAILS = dest_sg

                    banner = "SG naming conflict, using existing SG"
                    # DisplayName spacing
                    bannerCounter = len(banner)
                    bannerCounter = counter - bannerCounter

                    logger.info(f"""
                     \n\n
                     !!{'!'*counter}!
                     ! {banner + ' '*bannerCounter}!
                     ! Display Name: {sg["display_name"] + ' '*dnCounter}!
                     ! UUID - {DEST_SG_DETAILS["id"] + ' '*uuidCounter}!
                     !!{'!'*counter}!
                     \n\n
                    """)

        # Source Collection details
        try:
            if verbose or debug:
                logger.info("Pulling source collection details.")
            src_mapped_collections, src_guest_collections = get_colls_per_sg(
                    SRC_GCS_CLIENT, sg["id"])
        except globus_sdk.GlobusAPIError as e:
            if e.errors:
                logger.error(
                       "Error encountered retrieving source Collection detals")
                logger.error("(code, message)")
                for suberror in e.errors:
                    logger.error("Error pulling collection details")
                    logger.error(sg['id'])
                    logger.error(suberror.code, suberror.message)
        logger.info(f"\t{'#'*73}\n")

        # Create equivalent Mapped Collections on Dest SG
        logger.info("\n\t\tCreating equivalent Mapped Collections:")
        logger.info(f"\t\t{'_'*45}")
        if dry_run:
            logger.info(
                        "\t\t---------------DRY-RUN------------------------")
            logger.info(f"\t\t{'-'*45}\n")
            for coll in src_mapped_collections['data']:
                logger.info(f"\t\t- {coll['display_name']}\n")

        if verbose or debug:
            logger.info(f"\t\t\tOrig SG - {sg['id']}")
            if not dry_run:
                dst_sg_dtl = DEST_SG_DETAILS['id']
                logger.info(f"\t\t\tDest SG - {dst_sg_dtl}")
            logger.info("\t\t\tOrig. Mapped Collection Details:")
            logger.info(f"\t\t{src_mapped_collections}\n")
        logger.info(f"\t\t{'='*50}\n")

        if not dry_run:
            mapped_collection_mapping = create_collection(
                    XFER_Client,
                    Globus_SA_CLIENT_ID,
                    Globus_SA_CLIENT_SECRET,
                    DEST_ENDPOINT_ID,
                    DEST_GCS_CLIENT,
                    DEST_SG_DETAILS["id"],
                    src_mapped_collections,
                    DEST_GCS_MANAGER_DOMAIN_NAME,
                    SERVICE_USER,
                    SRC_GCS_CLIENT,
                    DEST_COLL_SUFFIX,
                    verbose,
                    debug,
                    public,
                    high_assurance,
                    no_high_assurance,
                    collections_to_skip
                    )

        if len(src_guest_collections["data"]) > 0:
            # Create equivalent Guest Collections on Dest SG/MColl's
            logger.info(
                    "\n\t\tCreating equivalent Guest Collections on Dest SG:")

            if dry_run:
                logger.info(
                        "\t\t---------------DRY-RUN------------------------")
                logger.info(f"\t\t- {coll['display_name']}\n")

            if verbose or debug:
                logger.info(f"\t\t\tOrig SG - {sg['id']}")
                if not dry_run:
                    dst_sg_dtl = DEST_SG_DETAILS['id']
                    logger.info(f"\t\t\tDest SG - {dst_sg_dtl}")
                logger.info("\t\t\tOrig. Guest Collection Details:")
                logger.info(f"\t\t{src_guest_collections['data']}\n")
            logger.info(
                    "\t\t====================================================")

            if not dry_run:
                guest_collection_mapping = create_collection(
                        XFER_Client,
                        Globus_SA_CLIENT_ID,
                        Globus_SA_CLIENT_SECRET,
                        DEST_ENDPOINT_ID,
                        DEST_GCS_CLIENT,
                        DEST_SG_DETAILS["id"],
                        src_guest_collections,
                        DEST_GCS_MANAGER_DOMAIN_NAME,
                        SERVICE_USER,
                        SRC_GCS_CLIENT,
                        DEST_COLL_SUFFIX,
                        verbose,
                        debug,
                        public,
                        high_assurance,
                        no_high_assurance,
                        collections_to_skip
                        )

            if debug and not dry_run:
                logger.debug(
                        "\n\n--------------------DEBUG--------------------")
                logger.debug("\nMapped Collection Mappings:")
                logger.debug(mapped_collection_mapping)
                logger.debug("\nGuest Collection Mappings:")
                logger.debug(guest_collection_mapping)
                logger.debug(
                        "--------------------DEBUG--------------------\n\n")


def get_addtl_colls(GCS_CLIENT, STORAGE_GATEWAY_UUID, COLLECTION_DATA,
                    filter=None):
    """
    Pull the remaining paginaed collections not included in our initial
    Collection list
    """

    # DEBUG
    src_collections = COLLECTION_DATA
    logger.debug(f"\n\n{'=*'*75} get_addtl_colls()")
    logger.debug(f"Starting Collection count: {len(src_collections['data'])}")
    # Check for additional collections
    if COLLECTION_DATA.get("has_next_page") is True:
        coll_has_next = True
        coll_next_marker = COLLECTION_DATA.get("marker")
        logger.debug(f"More collections to retrieve: {coll_next_marker}")
    else:
        logger.debug(
               f"Final Collection Count: {len(COLLECTION_DATA['data'])}")

    # If we've got more SG's, grab them!
    while coll_has_next:
        # Set our marker value
        logger.debug(f"\t\tRetrieving addtl Collections: {coll_next_marker}")

        # Retrieve the next set of collections
        more_src_collections = GCS_CLIENT.get_collection_list(
                filter=filter,
                marker=coll_next_marker,
                include="private_policies")

        logger.debug(f"Next_Marker: {more_src_collections.get('marker')}")

        # Append our additional SG details
        for coll in more_src_collections["data"]:
            if coll not in more_src_collections["data"]:
                src_collections["data"].append(coll)
                logger.debug("+++++++Collection added:")
                logger.debug(coll)
        #   if item not in more_src_collections["data"]:

        # Check for more SG's
        if more_src_collections.get("has_next_page") is True:
            # Set our marker value for the next iteration
            coll_next_marker = more_src_collections.get("marker")
            logger.debug(
                    f"Yet more Collections to retrieve: {coll_next_marker}")

        else:
            coll_has_next = False
            logger.debug(
                    f"Final Collection Count: {len(src_collections['data'])}")

            logger.debug("Our ending SG ")
            for coll in src_collections:
                logger.debug(f"ID: {coll['id']}")
            logger.debug(src_collections)

        # Cleaning up
        more_src_collections = {}
    logger.debug(f"\n\n{'=!'*75} get_addtl_colls()")
    return src_collections


def get_colls_per_sg(GCS_CLIENT, STORAGE_GATEWAY_UUID, debug=False):
    """
    Pull collections that are leveraging the Storage Gateway of interest
    """

    mapped_collection_details = GCS_CLIENT.get_collection_list(
                         query_params={
                             "filter": "mapped_collections",
                             "include": "private_policies",
                             "storage_gateway_id":
                             STORAGE_GATEWAY_UUID})
    if mapped_collection_details.get("has_next_page") is True:
        mapped_collection_details = get_addtl_colls(
                GCS_CLIENT,
                STORAGE_GATEWAY_UUID,
                mapped_collection_details,
                filter="mapped_collections")

    guest_collection_details = GCS_CLIENT.get_collection_list(
                         query_params={
                             "filter": "guest_collections",
                             "include": "private_policies",
                             "storage_gateway_id":
                             STORAGE_GATEWAY_UUID})

    if guest_collection_details.get("has_next_page") is True:
        guest_collection_details = get_addtl_colls(
                GCS_CLIENT,
                STORAGE_GATEWAY_UUID,
                guest_collection_details,
                filter="guest_collections")

    if len(mapped_collection_details["data"]) > 0:
        src_mapped_collections.append(mapped_collection_details["data"])
        logger.debug("Mapped Collection count")
        logger.debug(f"{'_'*55}")
        logger.debug(len(src_mapped_collections))
        logger.debug(f"{'-'*55}")
    logger.debug(f"ALL[SRC] - Mapped Collections for {STORAGE_GATEWAY_UUID}:")
    logger.debug(mapped_collection_details)

    if len(guest_collection_details["data"]) > 0:
        src_guest_collections.append(guest_collection_details["data"])
        logger.debug("Guest Collection count")
        logger.debug(f"{'_'*55}")
        logger.debug(len(src_guest_collections))
        logger.debug(f"{'-'*55}")
    logger.debug(f"ALL[SRC] - Guest Collections for {STORAGE_GATEWAY_UUID}:")
    logger.debug(guest_collection_details)

    return mapped_collection_details, guest_collection_details


def get_collection_details(XFER_Client,
                           SRC_GCS_CLIENT,
                           GUEST_COLLECTION_ID_ORIG,
                           collection_type=None,
                           verbose=False,
                           debug=False):
    """
    Retrive and return Guest Collection details
    ACL's and Roles
    """
    # Use the GCS Client to get a list of Roles on
    # the original Guest Collection
    ROLE_LIST = SRC_GCS_CLIENT.get_role_list(
            collection_id=GUEST_COLLECTION_ID_ORIG,
            include="all_roles")

    # Pull the nested Dictionary containing the Guest Collection details
    ORIGINAL_COLL_ROLES = ROLE_LIST["data"]
    logger.debug(f"Orig Collection Roles: {ORIGINAL_COLL_ROLES}")

    if collection_type is None:
        # Get our Original Guest Collection ACL's
        ORIGINAL_G_COLL_ACLs = XFER_Client.endpoint_acl_list(
            endpoint_id=GUEST_COLLECTION_ID_ORIG)
        ORIGINAL_G_COLL_ACLs = paginated_response(SRC_GCS_CLIENT,
                                                  ORIGINAL_G_COLL_ACLs,
                                                  "ACLs",
                                                  debug)

        logger.debug(f"Orig ACL's: {ORIGINAL_G_COLL_ACLs}")

        dict_of_collection_details = [ORIGINAL_G_COLL_ACLs,
                                      ORIGINAL_COLL_ROLES]
    else:
        # Mapped Collection, no ACL's to return
        dict_of_collection_details = [ORIGINAL_COLL_ROLES]

    return dict_of_collection_details


def update_acls_roles(XFER_Client,
                      DEST_GCS_CLIENT,
                      COLLECTION_ID_DEST,
                      action_type,
                      OBJ_DATA,
                      verbose=False, debug=False):
    """
    Update:
        Endpoint - Roles
        Mapped collection - Roles
        Guest collection - ACLs and Roles
    """

    if action_type == "acls":

        G_COLL_ACLS = OBJ_DATA

        for GUEST_ACL_TO_TRANSFER in G_COLL_ACLS["DATA"]:
            GUEST_ACL_TO_TRANSFER.pop('create_time')
            GUEST_ACL_TO_TRANSFER.pop('id')
            GUEST_ACL_TO_TRANSFER.pop('expiration_date')
            logger.info(
              f"\t\t\tCopying ACL's to new Guest: {COLLECTION_ID_DEST}")
            if verbose or debug:
                logger.info(f"\t\t\t{GUEST_ACL_TO_TRANSFER}\n")

            # aclAddResults = XFER_Client.add_endpoint_acl_rule(
            XFER_Client.add_endpoint_acl_rule(
                    COLLECTION_ID_DEST,
                    GUEST_ACL_TO_TRANSFER)

            if verbose or debug:
                logger.info(f"{'='*70}\n\n")

    if action_type == "roles":

        OBJ_ROLES = OBJ_DATA

        for OBJ_ROLE_TO_TRANSFER in OBJ_ROLES:
            OBJ_ROLE_TO_TRANSFER.pop('id')
            try:
                if COLLECTION_ID_DEST is not None:
                    OBJ_ROLE_TO_TRANSFER["collection"] = COLLECTION_ID_DEST
                    COLL_ID = COLLECTION_ID_DEST
                    logger.info(
                     f"\t\t\tCopying ROLE's to new collection: {COLL_ID}\n")
                    DEST_GCS_CLIENT.create_role(
                            OBJ_ROLE_TO_TRANSFER)
                else:
                    # We're updating Dest Endpoint's roles
                    logger.info(
                            f"\t\t\tCopying ROLE to new Endpoint: {
                                                OBJ_ROLE_TO_TRANSFER}"
                            )
                    DEST_GCS_CLIENT.create_role(
                            OBJ_ROLE_TO_TRANSFER)

                logger.debug(f"\t\t\t{OBJ_ROLE_TO_TRANSFER}\n")

            except globus_sdk.GlobusAPIError as e:
                errors = []
                if e.errors:
                    if verbose or debug:
                        logger.error("sub-errors encountered")
                        logger.error("(code, message)")
                    for suberror in e.errors:
                        if verbose or debug:
                            logger.critical(suberror.code,
                                            suberror.message)
                        errors.append([suberror.code, suberror.message])

            if verbose or debug:
                logger.info(f"{'='*70}\n\n")


def check_root_path(root_path, SERVICE_USER, Guest_Collection=False):
    """
    Check base_path for dynamic [e.g. '~' or $HOME
    """
    dynamic_path = False
    regexp = re.compile(r'~|HOME')
    if regexp.search(root_path):
        dynamic_path = True
        dynamic_paths.append(root_path)

    if not os.path.exists(root_path) or dynamic_path:
        return False
    else:
        return True


def create_collection(XFER_Client,
                      Globus_SA_CLIENT_ID,
                      Globus_SA_CLIENT_SECRET,
                      DEST_ENDPOINT_ID,
                      DEST_GCS_CLIENT,
                      SG_UUID,
                      COLLECTION_DATA,
                      DEST_GCS_MANAGER_DOMAIN_NAME,
                      SERVICE_USER,
                      SRC_GCS_CLIENT=None,
                      DEST_COLL_SUFFIX=None,
                      verbose=False,
                      debug=False,
                      public=False,
                      high_assurance=False,
                      no_high_assurance=False,
                      collections_to_skip=collections_to_skip):
    """
    Create Collection
    """

    gcoll_Dest = None
    coll_crte_rsp = []
    guest_collections = []
    USER_CREDENTIAL_ID = None
    USER_CRED_DETAILS = {}
    root_path_check = True
    high_assurance = high_assurance

    if verbose or debug:
        logger.info(f"\n\tCollections to skip: {collections_to_skip}\n")
        logger.info(f"\n{'-'*24}")
        if debug:
            logger.debug(f"Here's our Collection_DATA: \n{COLLECTION_DATA}")
        logger.info("==========================")

    # Mapped and Guest Collection ops
    for coll in COLLECTION_DATA:
        if coll["id"] in collections_to_skip:
            if verbose or debug:
                logger.warning(
                        f"(M) SKipping creating equivalent to {coll['id']}")
            continue

        orig_coll_id = coll["id"]
        connector_id = coll["connector_id"]
        posix_connector_id = "145812c8-decc-41f1-83cf-bb2a85a2a70b"

        root_path = coll.get("root_path")

        if not coll.get("root_path"):
            logger.debug(f"\n\n{'_'*75}")
            logger.debug(coll)
            logger.debug(f"\n\n{'+'*75}")

        # If suffix is specified
        if DEST_COLL_SUFFIX:
            if verbose or debug:
                logger.debug("Pre-Renaming values")
                logger.debug(coll)
            suffix = DEST_COLL_SUFFIX
            new_name = coll["display_name"]+suffix
            coll["display_name"] = new_name

        # Defaulting to creating collections as 'Private'
        coll["public"] = public

        # Update the Storage Gateway to our newly created Dest. SG
        coll["storage_gateway_id"] = SG_UUID

        # Cleaning up our source collections details for copying to our
        # dest. Endpoint/collection creation ops

        if high_assurance:
            logger.warning(
             "\t\t!! - Rm'ing 'disable_anonymous_writes' from collection.")
            coll.pop("disable_anonymous_writes", None)
            if coll.get("guest_auth_policy_id"):
                logger.warning(
                        "\t\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")
                logger.warning(
                 "\t\t!! - Rm'ing 'guest_auth_policy_id' from collection.")
                logger.warning(
                      "\t\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")
                coll.pop("guest_auth_policy_id", None)

        if coll.get("domain_name"):
            logger.warning(
                   "\t\t!! - Removing 'Domain' attribute from collection:")
            logger.warning(f"\t\tSource Collection - {coll['id']}")
            del coll["domain_name"]

        if coll.get("require_high_assurance"):
            logger.info(
             "!! - Rm'ing 'require_high_assurance' attribute collection:")
            logger.info(f"\tRemoved value - {coll['require_high_assurance']}")
            coll.pop("require_high_assurance", None)

        # Check if Collection 'root_path' exists on node
        if connector_id == posix_connector_id and coll.get("root_path"):
            root_path_check = check_root_path(root_path, SERVICE_USER)

        # If we're working on a Mapped Collection
        # if "guest" not in coll.get("collection_type"):
        if "mapped" == coll.get("collection_type"):
            coll.pop("created_at", None)
            coll.pop("connector_id", None)
            coll.pop("https_url", None)
            coll.pop("id", None)
            coll.pop("manager_url", None)
            coll.pop("require_mfa", None)
            coll.pop("root_path", None)
            coll.pop("deleted", None)
            coll.pop("high_assurance", None)
            coll.pop("last_access", None)
            coll.pop("tlsftp_url", None)
            coll.pop("authentication_timeout_mins", None)
            coll.pop("identity_id", None)
            coll.pop("domain_name", None)
            coll.pop("disable_anonymous_writes", None)
            coll.pop("subscription_admin_verified", None)

            try:
                COLL_ROLES = get_collection_details(
                        XFER_Client,
                        SRC_GCS_CLIENT,
                        orig_coll_id,
                        "Mapped")[0]

                # Create our Mapped Collection via GCS API call
                mcollection_creation_resp = DEST_GCS_CLIENT.create_collection(
                        coll)

                # Full MColl details
                MAPPED_COLLECTION_DEST = mcollection_creation_resp.full_data

                # MColl UUID
                new_mapped_collection_id = MAPPED_COLLECTION_DEST[
                        'data'][0]["id"]

                # Since we're updating a MColl, we're only updating Roles
                action_type = "roles"
                update_acls_roles(XFER_Client,
                                  DEST_GCS_CLIENT,
                                  new_mapped_collection_id,
                                  action_type,
                                  COLL_ROLES,
                                  verbose,
                                  debug)

                logger.info(
                    f"\t\tNew Mapped Collection: {new_mapped_collection_id}\n")
                coll_crte_rsp.append(
                        mcollection_creation_resp)
                collection_mapping.append(
                        {orig_coll_id: new_mapped_collection_id})
                collections_created.append(
                        {orig_coll_id: new_mapped_collection_id})

                if not root_path_check:
                    if verbose or debug:
                        logger.warning(
                             "\t\tMapped collection root_path does not exist.")
                        logger.warning(
                               f"\t\t[{new_mapped_collection_id}]:{root_path}")
                    non_existant_paths.append(root_path)

            except globus_sdk.GCSAPIError as err:
                logger.error("\n\n\t\t===============================")
                logger.error("\t\tError encountered while creating MColl")
                logger.error(f"\t\tError - {err}")
                logger.error(f"\t\tCollection Dictionary: {coll}")
                logger.error("===============================\n\n")

        # Add Guest Collection details to the appropriate tracking list
        else:
            guest_collections.append(coll)

    # Guest Collection ops
    if len(guest_collections) > 0:
        if verbose:
            logger.info(f"\t\tCreating Guest Collections: {guest_collections}")
        for coll in guest_collections:
            orig_mapped_collection_id = coll["mapped_collection_id"]
            orig_guest_collection_id = coll["id"]
            if orig_mapped_collection_id in collections_to_skip:
                if verbose or debug:
                    logger.warning(
                       f"\t\t(G) SKipping creating equivalent to {coll['id']}")
                continue
            root_path = coll["root_path"]
            # Check if Collection 'root_path' exists on node if a POSIX SG
            if connector_id == posix_connector_id:
                root_path_check = check_root_path(root_path,
                                                  SERVICE_USER, True)

            # Find our original Mapped Collection ID and
            # it's new equiv. Collection

            if debug:
                logger.info(
                      f"DEBUG------> COLLECTION_MAPPING: {collection_mapping}")
            for mapped_collection_pair in collection_mapping:
                if mapped_collection_pair.get(str(orig_mapped_collection_id)):
                    for key, value in mapped_collection_pair.items():
                        if mapped_collection_pair.get(
                                str(orig_mapped_collection_id)):
                            mcoll_pair_id = mapped_collection_pair[key]
                            # Setting our dest. Mapped Collection
                            coll["mapped_collection_id"] = mcoll_pair_id
                            if verbose or debug:
                                omc_id = orig_mapped_collection_id
                                nmc_id = coll['mapped_collection_id']
                                ogc_id = orig_guest_collection_id
                                logger.info("\t\n\t-------------------------")
                                logger.info("\t|Org. MColl == New MColl|")
                                logger.info("\t-------------------------")
                                logger.info(f"\t{omc_id} == {nmc_id}\n")
                                logger.info(f"\tOrig GColl ID: {ogc_id}")
                                logger.info("\t=========================\n\n")

            # Might need to revert and pass in high_assurance update
            # per SG if `--ha` isn't specified
            if not high_assurance or no_high_assurance:
                # Get a new GCS Authorizer with the `data_access` scope
                # tacked on to allow GColl ops
                dest_gcs_authorizer = get_scopes(Globus_SA_CLIENT_ID,
                                                 Globus_SA_CLIENT_SECRET,
                                                 DEST_ENDPOINT_ID,
                                                 coll["mapped_collection_id"],
                                                 )

                GCS_Client = get_gcs_client(DEST_GCS_MANAGER_DOMAIN_NAME,
                                            dest_gcs_authorizer)
            else:
                GCS_Client = DEST_GCS_CLIENT

            credentials = GCS_Client.get_user_credential_list(SG_UUID)
            if debug:
                logger.info(
                      f"DEBUG-------> Here's our cred response: {credentials}")
            for cred in credentials:
                if cred['storage_gateway_id'] == SG_UUID:
                    USER_CREDENTIAL_ID = cred['id']
                    if debug:
                        logger.info(f"Here's our user_cred_id: {cred['id']}")

            if USER_CREDENTIAL_ID is None:
                try:
                    logger.info(
                           "\n\t\tCreating Credential on new storage-gateway:")
                    logger.info(f"\t\t'username': {SERVICE_USER}")
                    logger.info(f"\t\t'storage_gateway_id': {SG_UUID}")

                    USER_CRED_DETAILS = GCS_Client.create_user_credential({
                        'DATA_TYPE': "user_credential#1.0.0",
                        'connector_id': coll['connector_id'],
                        'username': SERVICE_USER,
                        'storage_gateway_id': SG_UUID,
                    })

                except globus_sdk.GCSAPIError as err:
                    logger.error(f"Error encountered - {err}")

                logger.debug(
                            f"Newly created user_cred: {USER_CRED_DETAILS}")

            # Delete un-needed SRC collection details
            coll.pop("disable_anonymous_writes", None)
            coll.pop("created_at", None)
            coll.pop("connector_id", None)
            coll.pop("https_url", None)
            coll.pop("id", None)
            coll.pop("manager_url", None)
            coll.pop("require_mfa", None)
            coll.pop("root_path", None)
            coll.pop("deleted", None)
            coll.pop("high_assurance", None)
            coll.pop("last_access", None)
            coll.pop("tlsftp_url", None)
            coll.pop("authentication_timeout_mins", None)
            coll.pop("identity_id", None)
            coll.pop("sharing_restrict_paths", None)
            coll.pop("subscription_admin_verified", None)
            coll.pop("disable_anonymous_writes", None)
            coll.pop("domain", None)

            # Defaulting to creating collections as 'Private'
            coll["public"] = public

            # Update the Storage Gateway to our newly created Dest. SG
            coll["storage_gateway_id"] = SG_UUID

            # Attempt to create our equiv. Guest Collection if we have a
            # User Cred object
            try:
                if USER_CREDENTIAL_ID or USER_CRED_DETAILS.get("id"):
                    if USER_CREDENTIAL_ID:
                        coll["user_credential_id"] = USER_CREDENTIAL_ID
                    else:
                        # Set our Dest Storage Gateway UUID as the intended SG
                        coll["user_credential_id"] = USER_CRED_DETAILS["id"]

                if verbose:
                    logger.info(
                      "Preparing to create Guest Collection (ACTUAL):")

                coll_crte_rsp = DEST_GCS_CLIENT.create_collection(coll)
                GUEST_COLLECTION_DEST = coll_crte_rsp.full_data
                gcoll_Dest = GUEST_COLLECTION_DEST['data'][0]['id']

                if verbose:
                    logger.info(
                            f"GUEST_COLLECTION_DEST => {gcoll_Dest}")

                GUEST_COLLECTION_ID_DEST = gcoll_Dest
                collections_created.append(
                        {orig_guest_collection_id: gcoll_Dest})
                G_COLL_ACLs, G_COLL_ROLES = get_collection_details(
                        XFER_Client,
                        SRC_GCS_CLIENT,
                        orig_guest_collection_id)

                # Assign ACL's only to avoid race condition
                action_type = "acls"
                update_acls_roles(XFER_Client,
                                  DEST_GCS_CLIENT,
                                  GUEST_COLLECTION_ID_DEST,
                                  action_type,
                                  G_COLL_ACLs,
                                  verbose,
                                  debug)

                # Building in some time to make sure GCS is able
                # to sync with XFer before we attempt to update the Roles
                if debug or verbose:
                    logger.info(f"Guest Collection ROLES to transfer: {
                                G_COLL_ROLES}")

                # time.sleep(10)
                sync_wait_spinner_icon(25)

                # Assign Guest Collection roles's
                action_type = "roles"
                update_acls_roles(XFER_Client,
                                  DEST_GCS_CLIENT,
                                  GUEST_COLLECTION_ID_DEST,
                                  action_type,
                                  G_COLL_ROLES,
                                  verbose=verbose,
                                  debug=debug)
                logger.info(f"{'='*70}\n\n")

            except globus_sdk.GlobusAPIError as e:
                errors = []
                if e.errors:
                    if verbose or debug:
                        logger.error("(code, message)")
                    for suberror in e.errors:
                        if verbose or debug:
                            logger.error(
                                f"{suberror.code}, {suberror.message}")
                        errors.append(
                                [suberror.code, suberror.message])
                collection_creation_errors.append(
                        {orig_guest_collection_id: errors})

            if not root_path_check and gcoll_Dest is not None:
                if verbose or debug:
                    collection_UUID = gcoll_Dest
                    logger.info("Guest collection root_path does not exist:")
                    logger.info(f"\t{collection_UUID}: {root_path}")
                non_existant_paths.append(root_path)

    return collection_mapping


def print_results(storage_gateways_created,
                  storage_gateway_creation_errors,
                  collections_created,
                  collection_creation_errors,
                  non_existant_paths,
                  dynamic_paths,
                  SERVICE_USER,
                  ):

    # Return our results
    logger.info(
            f"\n\nStorage Gateways created [{len(storage_gateways_created)}]:")
    logger.info(
          "==================================================================")
    for sg in storage_gateways_created:
        logger.info(f"\t\tCreated {sg} on the dest Endpoint")

    if len(storage_gateway_creation_errors) > 0:
        sg_errors = len(storage_gateway_creation_errors)
        logger.info(f"\n\nFailed to create [{sg_errors}] Storage Gateways:")
        logger.info(
            "==============================================================")
        for sg in storage_gateway_creation_errors:
            logger.warning(
                    f"\t\tEncountered errors while creating {sg} on dest")

    logger.info(f"\n\nCollections created [{len(collections_created)}]:")
    logger.info(
        "==================================================================")
    for coll in collections_created:
        logger.info(f"\t\tCreated {coll} on the dest Endpoint")
    if len(collection_creation_errors) > 0:
        coll_errors = len(collection_creation_errors)
        logger.info(f"\n\nFailed to create [{coll_errors}] Collections:")
        logger.info(
            "==============================================================")
        for coll in collection_creation_errors:
            logger.info(
                    f"\t\tEncountered errors while creating {coll} on dest.")

    if len(non_existant_paths) > 0 or len(dynamic_paths) > 0:
        paths_errors = len(non_existant_paths)
        logger.info(
                f"\n\nCollection base_paths to investigate [{paths_errors}]:")
        logger.info(
              "==============================================================")
        for path in non_existant_paths:
            p = path
            logger.info(f"\t\tPath does not exist or dynnamic path: {p}")
        if len(dynamic_paths) > 0:
            logger.info("Collection base path's included a dynamic value:")
            logger.info(
                    "------------------------------------------------------\n")
            logger.info(
                    "!! Please ensure that the paths to new Guest !!")
            logger.info(
                   "!! collections exists, and are accessible to the local !!")
            logger.info(f"!! user: \"{SERVICE_USER}\" !!\n\n")
            logger.info(
                    "======================================================\n")


def sync_wait_spinner_icon(spin_wait):
    """
    Print a spinning cursor while we wait on GCS/Xfer syncing
    """

    spinner_chars = ['—', '\\', '|', '/']
    spin = 0
    # Start the loading message.
    print("\n\tAwaiting sync... ", end="", flush=True)

    # Wait icon printout
    try:
        while spin <= spin_wait:
            for char in spinner_chars:
                print(
                    f"\rPending GCS->XFer sync... {char} ", end="", flush=True)
                time.sleep(0.1)
            spin += 1
        print()
    except KeyboardInterrupt:
        print(
         "\rCancelling sync pause! (CTRL-C once more to halt script execution)"
         )

    print("Continuing to Role operations.\n\n")


def paginated_response(SRC_GCS_Client,
                       src_object_resp,
                       obj_type,
                       debug=False,
                       XFER_Client=None,
                       storage_gateway_id=None,
                       collection_id=None):
    """
    Check for pagination, pull more details as needed
    """
    obj_response_has_next = False

    src_objects = src_object_resp
    # Checking for more objects
    if src_object_resp.get("has_next_page") is True:
        obj_response_has_next = True
        obj_response_next_marker = src_object_resp.get("marker")
        logger.debug("More entries's to retrieve")
    elif obj_type != "ACLs":
        logger.debug(
               f"Final {obj_type} count: {len(src_object_resp['data'])}")

    # If we've got more SG's, grab them!
    while obj_response_has_next:
        # Set our marker value
        logger.debug(
                f"\t\tRetrieving addtl entries:{obj_response_next_marker}")

        if obj_type == "Storage-Gateway":
            # Retrieve the next set of SG's
            more_src_objects = get_storage_gateway_details(
                    SRC_GCS_Client,
                    obj_response_next_marker)
        elif obj_type == "ACLs":
            # Retrieve the next set of ACL's if any
            more_src_objects = XFER_Client.endpoint_acl_list(
                endpoint_id=collection_id)
        elif obj_type == "Collection":
            # Retrieve the next set of SG's
            pass
        elif obj_type == "Endpoint_Roles":
            # Retrieve the next set of SG's
            more_src_objects = SRC_GCS_Client.get_role_list(
                    include="all_roles",
                    marker=obj_response_next_marker)

        if debug:
            logger.debug(f"Next_Marker: {
                         more_src_objects.get('marker')}")

        # Append our additional SG details
        for item in more_src_objects["data"]:
            if item not in src_objects["data"]:
                src_objects["data"].append(item)

        # Check for more objects
        if more_src_objects.get("has_next_page") is True:
            # Set our marker value for the next iteration
            obj_response_next_marker = more_src_objects.get("marker")

        else:
            obj_response_has_next = False
            logger.debug(
                    f"Final {obj_type} Count: {len(src_objects['data'])}")

            if debug:
                logger.debug("Our ending {obj_type} ")
                for obj in src_objects:
                    logger.debug(f"ID: {obj['id']}")
                logger.debug(src_objects)

        # Cleaning up
        more_src_objects = {}

    return src_objects


def main():

    # Create empty vars for later user
    debug = False
    SRC_ENDPOINT_ID = ""
    DEST_ENDPOINT_ID = ""
    Globus_SA_CLIENT_ID = ""
    Globus_SA_CLIENT_SECRET = ""
    SRC_GCS_MANAGER_DOMAIN_NAME = ""
    DEST_GCS_MANAGER_DOMAIN_NAME = ""
    SERVICE_USER = ""

    # GetOpt error/help message
    error_message = """
    \nMissing required arguments, re-execute with:
    "-h/--help" to view arguments.\n\n
    """

    # If we didn't get any options error out
    if len(sys.argv) == 1:
        print(error_message)
        sys.exit(3)

    parser = argparse.ArgumentParser()
    parser.add_argument(
       "--src-endpoint", required=True,
       help="""
       Your source Endpoint UUID [e.g. 16599fe6-d9a6-31a4-b794-4da126f35d3a]
       """)
    parser.add_argument(
            "--src-endpoint-fqdn", required=True,
            help="Your Source Endpoint FQDN [e.g. e3cbc5.bd7c.gaccess.io")
    parser.add_argument(
     "--dst-endpoint", required=True,
     help="""
     Your destination Endpoint UUID [e.g. 26599ge6-d9a6-51b4-7724-3da126f35d34]
     """)
    parser.add_argument(
            "--dst-endpoint-fqdn", required=True,
            help="Your Dest. Endopint FQDN [e.g. a4adz1.ad7c.gaccess.io]\n")
    parser.add_argument(
            "--dst-collection-suffix",
            type=str,
            help="Suffix to be added to dest. collections [default: '']\n")
    parser.add_argument(
            "--identity-domain", required=True,
            help="""
            Identity Domain for use in ID mapping policy [e.g. umn.edu\n
            """)
    parser.add_argument(
            "--service-account-uuid", required=True,
            help="Your Globus Service Account UUID\n")
    parser.add_argument(
            "--service-account-secret", required=True,
            help="Your Globus Service ACcount Secret\n")
    parser.add_argument(
           "--local-svc-account", required=True,
           help="""
           Your local OS account that your Globus SA will map to for operations
           \n""")
    parser.add_argument(
            "--verbose",
            help="Increased verbosity", action="store_true")
    parser.add_argument(
            "--debug",
            help="More verbose output beyond 'verbose'\n", action="store_true")
    parser.add_argument(
            "--public",
            help="Allow public visibility to Collections [default: Private]\n",
            action="store_true")
    parser.add_argument(
            "--ha",
            help="Force HA SG/Collection creation [default: False]\n",
            action="store_true")
    parser.add_argument(
            "--no-ha",
            help="Force no-HA SG/Collection creation [default: False]\n",
            action="store_true")
    parser.add_argument(
            "--skip-collections",
            type=str,
            help="Comma separated list of collections to skip\n")
    parser.add_argument(
            "--dry-run",
            help="Print out details on actions to be taken [default: False]\n",
            action="store_true")
    parser.add_argument(
            "--force",
            help="Ignore storage-gateway creration errors",
            action="store_true")
    parser.add_argument(
            "--version",
            help="Print migration example script version\n",
            action="store_true")

    args = parser.parse_args()

    ###########################################################################
    # Note:
    #   Intentinoally requiring Endpoint FQDN's as an additional safety measure
    #   rather than pulling from GCS Client
    ###########################################################################
    SRC_ENDPOINT_ID = args.src_endpoint
    SRC_GCS_MANAGER_DOMAIN_NAME = args.src_endpoint_fqdn
    DEST_ENDPOINT_ID = args.dst_endpoint
    DEST_GCS_MANAGER_DOMAIN_NAME = args.dst_endpoint_fqdn
    DEST_COLL_SUFFIX = args.dst_collection_suffix
    identity_Domain = args.identity_domain
    Globus_SA_CLIENT_ID = args.service_account_uuid
    Globus_SA_CLIENT_SECRET = args.service_account_secret
    SERVICE_USER = args.local_svc_account
    verbose = args.verbose
    debug = args.debug
    public = args.public
    high_assurance = args.ha
    no_high_assurance = args.no_ha
    force = args.force
    if args.skip_collections is not None:
        collections_to_skip = args.skip_collections.split(',')
    else:
        collections_to_skip = []
    dry_run = args.dry_run
    version = args.version

    if version:
        print(f"\nEndpoint Migration example script v{migrater_version}\n")
        sys.exit(0)

    # Set our Transfer scopes
    TRANSFER_SCOPES = scopes.TransferScopes.all
    if verbose and debug:
        print(f"SRC_ENDPOINT_ID              = {SRC_ENDPOINT_ID}")
        print(f"SRC_GCS_MANAGER_DOMAIN_NAME  = {SRC_GCS_MANAGER_DOMAIN_NAME}")
        print(f"DEST_ENDPOINT_ID             = {DEST_ENDPOINT_ID}")
        print(f"DEST_GCS_MANAGER_DOMAIN_NAME = {DEST_GCS_MANAGER_DOMAIN_NAME}")
        print(f"DEST_COLL_SUFFIX             = {DEST_COLL_SUFFIX}")
        print(f"identity_Domain              = {identity_Domain}")
        print(f"Globus_SA_CLIENT_ID          = {Globus_SA_CLIENT_ID}")
        print(f"Globus_SA_CLIENT_SECRET      = {Globus_SA_CLIENT_SECRET}")
        print(f"SERVICE_USER                 = {SERVICE_USER}")
        print(f"verbose                      = {verbose}")
        print(f"debug                        = {debug}")
        print(f"public                       = {public}")
        print(f"high_assurance               = {high_assurance}")
        print(f"no-high_assurance            = {no_high_assurance}")
        print(f"force                        = {force}")
        print(f"skip_collections             = {collections_to_skip}")

    # Get Auth'd
    logger.info("Authenticating")
    AUTH_CLIENT = globus_sdk.ConfidentialAppAuthClient(Globus_SA_CLIENT_ID,
                                                       Globus_SA_CLIENT_SECRET)
    AUTH_TOKENS = AUTH_CLIENT.oauth2_client_credentials_tokens(
            requested_scopes=TRANSFER_SCOPES)
    AUTH_TOKEN_INFO = (
        AUTH_TOKENS.by_resource_server["transfer.api.globus.org"])
    XFER_TOKEN = AUTH_TOKEN_INFO["access_token"]

    # Setup our XFer client for Guest collection actions
    xfer_authorizer = globus_sdk.AccessTokenAuthorizer(XFER_TOKEN)
    XFER_Client = globus_sdk.TransferClient(authorizer=xfer_authorizer)

    # Setup our Src GCS client for Storage-Gateway/Collection actions
    src_gcs_authorizer = get_scopes(Globus_SA_CLIENT_ID,
                                    Globus_SA_CLIENT_SECRET,
                                    SRC_ENDPOINT_ID)
    SRC_GCS_Client = get_gcs_client(SRC_GCS_MANAGER_DOMAIN_NAME,
                                    src_gcs_authorizer)

    if SRC_ENDPOINT_ID != DEST_ENDPOINT_ID:
        # Setup our Dest GCS client for Storage-Gateway/Collection actions
        dest_gcs_authorizer = get_scopes(Globus_SA_CLIENT_ID,
                                         Globus_SA_CLIENT_SECRET,
                                         DEST_ENDPOINT_ID)

        DEST_GCS_Client = get_gcs_client(DEST_GCS_MANAGER_DOMAIN_NAME,
                                         dest_gcs_authorizer)
    elif DEST_COLL_SUFFIX != '':
        # If an intra-Endpoint copy, re-use our pre-existing/valid GCS client
        DEST_GCS_Client = SRC_GCS_Client
    else:
        print("""
        When performing an intra-Endpoint copy the
           "--dst_collection_suffix" option must be provided.""")

    # Get initial source Storage Gateway and Mapped Collection detalis
    logger.info("Retrieving source Endpoint details")

    # Retrieve EP role assignments from our source EP
    src_endpoint_roles = SRC_GCS_Client.get_role_list(include="all_roles")
    src_endpoint_roles = paginated_response(SRC_GCS_Client,
                                            src_endpoint_roles,
                                            "Endpoint_Roles",
                                            debug)

    logger.debug(f"Endpoint Roles: {src_endpoint_roles}")
    logger.debug(f"Updating Dest endpoint roles: {DEST_ENDPOINT_ID}")
    # Update Dest Endpoint role assignments
    COLLECTION_ID_DEST = None
    action_type = "roles"
    update_acls_roles(XFER_Client,
                      DEST_GCS_Client,
                      COLLECTION_ID_DEST,
                      action_type,
                      src_endpoint_roles,
                      verbose,
                      debug)

    # Get initial source Storage Gateway and Mapped Collection detalis
    logger.info("Retrieving source Storage Gateway/Collection details")

    # sg_has_next = False
    src_storage_gateways = get_storage_gateway_details(SRC_GCS_Client)
    src_storage_gateways = paginated_response(SRC_GCS_Client,
                                              src_storage_gateways,
                                              "Storage-Gateway", debug)

    if debug:
        logger.debug("Here's our initial Src SG Details")
        logger.debug(src_storage_gateways)

    # Create our Destination Endpoint storage-gateway/collection equivalents
    if dry_run:
        logger.info(
                "!!!!!!!!!!!!!!!!!!!!!!!!! DRY RUN !!!!!!!!!!!!!!!!!!!!!!!!!")
    else:
        logger.info("Creating resources on destination Endpoint")

    create_storage_gateway(
            XFER_Client,
            identity_Domain,
            DEST_GCS_MANAGER_DOMAIN_NAME,
            DEST_ENDPOINT_ID,
            SERVICE_USER,
            DEST_GCS_Client,
            SRC_GCS_Client,
            src_storage_gateways,
            Globus_SA_CLIENT_ID,
            Globus_SA_CLIENT_SECRET,
            DEST_COLL_SUFFIX,
            collections_to_skip,
            verbose,
            debug,
            public,
            high_assurance,
            no_high_assurance,
            force,
            dry_run)

    if dry_run:
        logger.info(
            f"\nStorage Gateways to be created: {
                len(storage_gateways_created)
            }")
        logger.info(
            f"\nMapped Collections to be created: {
                len(src_mapped_collections)
                }")
        if debug or verbose:
            logger.info("\tCollections to be copied:")
            for coll in src_mapped_collections:
                logger.info(coll[0]['id'])
        logger.info(
            f"\nGuest Collections to be created: {
                len(src_guest_collections)
                }")
        if debug or verbose:
            logger.info("\tCollections to be copied:")
            for coll in src_guest_collections:
                logger.info(coll[0]['id'])
        logger.info("\n\t\tEnd of DRY RUN")
        logger.info(
               "=========================-=========================")
    else:
        print_results(storage_gateways_created,
                      storage_gateway_creation_errors,
                      collections_created,
                      collection_creation_errors,
                      non_existant_paths,
                      dynamic_paths,
                      SERVICE_USER,
                      )


if __name__ == '__main__':
    main()
