import boto3, argparse, sys, json, re
from aws_escalate import escalate

DEFAULT_IAM_AWS_REGION = "us-east-1"
NEW_TARGETS_FOUND_AT_RUNTIME = False

def main(args):
    global NEW_TARGETS_FOUND_AT_RUNTIME


    access_key_id = args.access_key_id
    secret_access_key = args.secret_access_key
    session_token = args.session_token
    log_file = args.log_file
    exclusions_regex = args.aws_roles_exluded

    # First we attempt to login with the keys provided as arguments
    # Then we try to use the profile provided or the default profile 
    # Last, we ask for the keys to the use
    init_session = None

    if access_key_id is None or secret_access_key is None:
        default_profile_available = False
        try:
            init_session = boto3.Session()
            init_session.client("sts").get_caller_identity()
            default_profile_available = True
        except:
            default_profile_available = False
            init_session = None

        if not default_profile_available:
            print("IAM keys not passed in as arguments, enter them below:")
            access_key_id = input("  Access Key ID: ")
            secret_access_key = input("  Secret Access Key: ")
            session_token = input("  Session Token (Leave blank if none): ")
            if session_token.strip() == "":
                session_token = None
            if access_key_id.strip() == "":
                access_key_id = None
            if secret_access_key.strip() == "":
                secret_access_key = None

    if access_key_id is None and init_session is None:
        print("No valid credentials provided.")
        print("Exiting.")
        sys.exit(1)

    if init_session is None and (access_key_id is not None) and session_token is None:
        init_session = boto3.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=DEFAULT_IAM_AWS_REGION,
        )
    elif (
        init_session is None
        and (access_key_id is not None)
        and session_token is not None
    ):
        init_session = boto3.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            aws_session_token=session_token,
            region_name=DEFAULT_IAM_AWS_REGION,
        )

    sts = init_session.client("sts")

    init_identity = sts.get_caller_identity()["Arn"]
    print(f"Script initially running as {init_identity}.")
    print(f"Running AWS Escalate from the identity {init_identity}")
    try:
        escalate(init_session)
    except Exception as e:
        pass

    all_accounts, all_roles = discover_targets(init_session,exclusions_regex)

    # concatenate all the roles we discovered with the list provided as input
    if args.aws_accounts_list is not None:
        input_accounts = json.load(
            open(
                args.aws_accounts_list,
            )
        )
        all_accounts.update(set(input_accounts))

    # concatenate all the account ids we
    # discovered with the list provided as input
    if args.aws_roles_list is not None:
        input_roles = json.load(open(args.aws_roles_list))

        all_roles.update(set(input_roles))

    initial_credentials = {
        "AccessKeyId": init_session.get_credentials().access_key,
        "SecretAccessKey": init_session.get_credentials().secret_key,
        "SessionToken": init_session.get_credentials().token,
        "SourceAccount": parse_resource_arn(init_identity)[3],
        "SourceRole": "/".join(parse_resource_arn(init_identity)[5:]),
        "ExternalId": None,
    }

    print("### Begin lateral movement")
    current_list_roles = list(all_roles)
    current_list_accounts = list(all_accounts)
    init_flag = True
    # Initial scan
    if len(all_roles) != 0 or  len(all_accounts) != 0 :
        NEW_TARGETS_FOUND_AT_RUNTIME = True
    else : 
        NEW_TARGETS_FOUND_AT_RUNTIME = False
        
    # Restart the scan at the end of each execution whenever something was discovered    
    exec_count = 0
    while NEW_TARGETS_FOUND_AT_RUNTIME :
        exec_count += 1
        if init_flag :
            print("############################################################## - [{}] - First execution !!! #####################################################".format(exec_count))
            # For debugging only - to remove
            init_flag = False

        else :
             print("########################################### - [{}] - Starting the execution again because someting new was discovered !!! ######################".format(exec_count))
        
        NEW_TARGETS_FOUND_AT_RUNTIME = False
        current_list_accounts,current_list_roles = enumerate_org(current_list_accounts, current_list_roles,exclusions_regex, initial_credentials, log_file,blacklist=set())


def discover_targets(init_session,exclusion_regex):
    all_roles = set()
    all_accounts = set()
    
    
    # Retrieve the roles from the organization if possible
    try :
        org_accounts = perform_list_action(init_session.client("organizations"), "list_accounts", "Accounts")
        for __acc in org_accounts :
            all_accounts.add(__acc["Id"])
    except Exception as e:
        pass

    # Retrieve the list of roles
    # in the current account if possible
    try :
        roles = perform_list_action(init_session.client("iam"), "list_roles", "Roles")
    except Exception as e :
        roles = []
        
    for r in roles:
        arn_parsing = parse_resource_arn(r["Arn"])
        if arn_parsing[5].startswith("role"):
            all_roles.add(arn_parsing[6])
        all_accounts.add(arn_parsing[3])

    # Analyze all the policy statements (Resources, Principals)
    # and extract the roles and account IDs we find.
    try :
        policies = perform_list_action(
        init_session.client("iam"), "list_policies", "Policies", args={"Scope": "Local"}
    )
    except Exception as e:
        policies = []

    for policy in policies:
        default_version_id = init_session.client("iam").get_policy(
            PolicyArn=policy["Arn"]
        )["Policy"]["DefaultVersionId"]
        policy_doc = init_session.client("iam").get_policy_version(
            PolicyArn=policy["Arn"], VersionId=default_version_id
        )["PolicyVersion"]["Document"]
        resource_refs = re.findall(
            "arn:[^:\n]*:[^:\n]*:[^:\n]*:[^:\n]*:[^:\/\n]*[:\/]?[^ \"]*",
            json.dumps(policy_doc),
        )
        for ref in resource_refs:
            arn_parsing = parse_resource_arn(ref)
            if arn_parsing[5].startswith("role"):
                all_roles.add(arn_parsing[6])
            all_accounts.add(arn_parsing[3])

    found_accounts, found_roles = scan_inline_policies(init_session.client("iam"))
    all_accounts.update(found_accounts)
    all_roles.update(found_roles)
    
    # exclude the designated roles
    __all_roles = set(all_roles)
    for r in __all_roles :
        if bool(re.search(exclusion_regex,r)) :
            all_roles.remove(r)
            
    return all_accounts, all_roles


def scan_inline_policies(client):
    target_resources = {"role", "user", "group"}
    local_all_roles = set()
    local_all_accounts = set()
    identity_list = []
    inline_policy_list = []

    for target_resource in target_resources:
        try :
            identity_list = perform_list_action(
            client, f"list_{target_resource}s", f"{target_resource}s".capitalize()
        )
        except Exception as e :
            pass

        for identity in identity_list:
            identity_name = identity[f"{target_resource}".capitalize() + "Name"]
            
            try:
                inline_policy_list = perform_list_action(
                client,
                f"list_{target_resource}_policies",
                "PolicyNames",
                {f"{target_resource}".capitalize() + "Name": identity_name},
            )
            except:
                pass
                
            try:
                for policy_name in inline_policy_list:
                    arguments = {
                    f"{target_resource}".capitalize() + "Name": identity_name,
                    "PolicyName": policy_name,
                }
                    policy_doc = eval(
                    f'client.get_{target_resource}_policy(**arguments)["PolicyDocument"]'
                )
                    resource_refs = re.findall(
                    'arn:[^:\n]*:[^:\n]*:[^:\n]*:[^:\n]*:[^:\/\n]*[:\/]?[^ "]*',
                    json.dumps(policy_doc),
                )
                    for ref in resource_refs:
                        arn_parsing = parse_resource_arn(ref)
                        if arn_parsing[5].startswith("role"):
                            local_all_roles.add(arn_parsing[6])
                        local_all_accounts.add(arn_parsing[3])
            except:
                pass                 

    return local_all_accounts, local_all_roles


def perform_list_action(client, api_call_name, field_name, args=None):
    final_list = []
    result = None
    if args is None:
        result = eval(f"client.{api_call_name}()")
    else:
        result = eval(f"client.{api_call_name}(**args)")

    final_list = final_list + result[field_name]
    truncated = result["IsTruncated"]

    while truncated:
        args["Marker"] = result["Marker"]
        result = eval(f"client.{api_call_name}(**args)")
        final_list = final_list + result[field_name]
        truncated = result["IsTruncated"]

    return final_list


def enumerate_org(
    accounts, roles,exclusions_regex, creds, log_file, externalIDs=None, blacklist=set(), recursing=False
):
    local_blacklist = blacklist
    

    for account in accounts:
        for role in roles:
            result = None
            track_id = "{}-->{}".format(
                "{}::{}".format(creds["SourceAccount"], creds["SourceRole"]),
                "{}::{}".format(account, role),
            )
            if track_id not in local_blacklist:
                local_blacklist.add(track_id)
                result = move(role, account, creds,exclusions_regex, role_list=roles, account_list=accounts)

            if bool(result):
                # TODO : implement externalId
                log_entry = "Assume role found | {} --> {}".format(
                    "{}::{}".format(creds["SourceAccount"], creds["SourceRole"]),
                    "{}::{}".format(result["SourceAccount"], result["SourceRole"]),
                )
                print(log_entry)
                log(log_entry, log_file)
                print("-" * len(log_entry))
                enumerate_org(
                    accounts, 
                    roles,
                    exclusions_regex,   
                    result,
                    log_file,
                    externalIDs=None,
                    blacklist=local_blacklist,
                    recursing=True,
                )
    return list(accounts)[:],list(roles)[:]


def move(roleName: str, accountID: str, withCreds: dict,exclusions_regex: str,role_list=None,account_list=None):
    """
    roleName:  The role we are trying to assume
    accountID: The ID of the target account
    withCreds: The Credentials to use
        {
         "AccessKeyId":"",
         "SecretAccessKey":"",
         "SessionToken":"",
         "SourceAccount":"",
         "SourceRole":"",
         "ExternalId": None
        }

        return: creds {
                       "AccessKeyId":"",
                       "SecretAccessKey":"",
                       "SessionToken":"",
                       "SourceAccount":"",
                       "SourceRole":"",
                       "ExternalId": None
                      }

                OR

                None
    """
    
    global NEW_TARGETS_FOUND_AT_RUNTIME
    
    
    if accountID == withCreds["SourceAccount"] and roleName == withCreds["SourceRole"]:
        return None

    args = {
        "aws_access_key_id": withCreds["AccessKeyId"],
        "aws_secret_access_key": withCreds["SecretAccessKey"],
    }
    if "SessionToken" in withCreds and bool(withCreds["SessionToken"]) != False:
        args["aws_session_token"] = withCreds["SessionToken"]

    # if it is a role in our account, we patch it
    # editRolePolicy(roleName,accountID,action="patch")
    # print(f"role {roleName} in {accountID} patched")
    # get the sts client with the new credentails
    sts_client = boto3.client("sts", **args)

    try:
        if "ExternalId" in withCreds and bool(withCreds["ExternalId"]) != False:
            # Use the externalID provided
            sts_response = sts_client.assume_role(
                RoleArn=f"arn:aws:iam::{accountID}:role/{roleName}",
                RoleSessionName="IamReviewSessionName",
            )
            print(
                "Running AWS Escalate from the identity {}".format(
                    sts_response["AssumedRoleUser"]["Arn"]
                )
            )
            sts_response = sts_response["Credentials"]

            creds = {
                "AccessKeyId": sts_response["AccessKeyId"],
                "SecretAccessKey": sts_response["SecretAccessKey"],
                "SessionToken": sts_response["SessionToken"],
                "SourceAccount": accountID,
                "ExternalId": withCreds["ExternalId"],
                "SourceRole": roleName,
            }

            escalation_session = boto3.Session(
                aws_access_key_id=sts_response["AccessKeyId"],
                aws_secret_access_key=sts_response["SecretAccessKey"],
                aws_session_token=sts_response["SessionToken"],
                region_name=DEFAULT_IAM_AWS_REGION,
            )
            try:
                escalate(escalation_session)
            except Exception as e:
                print(e)

        else:
            sts_response = sts_client.assume_role(
                RoleArn=f"arn:aws:iam::{accountID}:role/{roleName}",
                RoleSessionName="IamReviewSessionName",
            )
            identity_ = sts_response["AssumedRoleUser"]["Arn"]
            print("Running AWS Escalate from the identity {}".format(identity_))
            sts_response = sts_response["Credentials"]

            creds = {
                "AccessKeyId": sts_response["AccessKeyId"],
                "SecretAccessKey": sts_response["SecretAccessKey"],
                "SessionToken": sts_response["SessionToken"],
                "SourceAccount": accountID,
                "SourceRole": roleName,
                "ExternalId": None,
            }

            escalation_session = boto3.Session(
                aws_access_key_id=sts_response["AccessKeyId"],
                aws_secret_access_key=sts_response["SecretAccessKey"],
                aws_session_token=sts_response["SessionToken"],
                region_name=DEFAULT_IAM_AWS_REGION,
            )
            try:
                # Try to escalate from with our new privileges
                escalate(escalation_session)
            except Exception as e:
                pass
               
            # Discover new roles and accounts from our new account   
             
            try:
                found_accounts, found_roles = discover_targets(escalation_session,exclusions_regex)
                new_acc = found_accounts.union(set(account_list)) - found_accounts.intersection(set(account_list))
                for acc in new_acc :
                    if acc not in account_list :
                        NEW_TARGETS_FOUND_AT_RUNTIME = True
                        print("Discovered new AWS Account :: {}".format(acc))
                        account_list.append(acc)
                        
                new_rol = found_roles.union(set(role_list)) - found_roles.intersection(set(role_list))
                for rol in new_rol :
                    if rol not in role_list :
                        NEW_TARGETS_FOUND_AT_RUNTIME = True
                        print("Discovered new role :: {}".format(rol))
                        role_list.append(rol)
                
            except Exception as e:
                print("An Exception occured while discovering new targets ...")
                print(e)


        # if it is a role in our account, we revert the modifications
        # editRolePolicy(roleName,accountID,action="revert")
        # print(f"role {roleName} reverted after successfull role assumption.")
        return creds
    except Exception as e:
        # if it is a role in our account, we revert the modifications
        # editRolePolicy(roleName,accountID,action="revert")
        # print(f"role {roleName} reverted after an error.")
        # print("Exception message :: ",e)
        return None

    return None


def parse_resource_arn(string):
    arn_pattern = "^arn:(?P<Partition>[^:\n]*):"
    arn_pattern += "(?P<Service>[^:\n]*):(?P<Region>[^:\n]*):"
    arn_pattern += "(?P<AccountID>[^:\n]*):"
    arn_pattern += "(?P<Ignore>(?P<ResourceType>[^:\/\n]*)"
    arn_pattern += "[:\/])?(?P<Resource>.*)$"
    r = re.findall(arn_pattern, string)
    return r[0]


def log(data, log_file):
    with open(log_file, "a") as logfile:
        logfile.write(data + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="""
        This tool was made to help cloud security professionals enumerate their AWS Organizations environment looking for potential lateral moves and privilege escalation paths."""
    )
    parser.add_argument(
        "--access-key-id",
        required=False,
        default=None,
        help="The AWS access key ID to use for authentication.",
    )
    parser.add_argument(
        "--secret-access-key",
        required=False,
        default=None,
        help="The AWS secret access key to use for authentication.",
    )
    parser.add_argument(
        "--session-token",
        required=False,
        default=None,
        help="The AWS session token to use for authentication, if there is one.",
    )

    parser.add_argument(
        "--aws-accounts-list",
        required=False,
        default=None,
        help="A JSON file containing a list of known AWS account IDs.",
    )
    parser.add_argument(
        "--aws-roles-list",
        required=False,
        default=None,
        help="A JSON file containing a list of known roles.",
    )
    parser.add_argument(
        "--aws-roles-exluded",
        required=False,
        default="^(AWSReserved|AWSServiceRoleFor|aws-reserved/|aws-service-role/|AWS-).*",
        help="A REGEX used to exclude several roles from the discovery process.",
    )
    parser.add_argument(
        "--log-file",
        required=False,
        default="lateral_movement.log",
        help="The log file.",
    )

    args = parser.parse_args()
    main(args)
