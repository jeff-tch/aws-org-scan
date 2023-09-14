
# IAM - AWS Organizations Scanner 

         __          _______        ____                   _____                 
        /\ \        / / ____|      / __ \                 / ____|                
       /  \ \  /\  / / (___ ______| |  | |_ __ __ _ _____| (___   ___ __ _ _ __  
      / /\ \ \/  \/ / \___ \______| |  | | '__/ _` |______\___ \ / __/ _` | '_ \ 
     / ____ \  /\  /  ____) |     | |__| | | | (_| |      ____) | (_| (_| | | | |
    /_/    \_\/  \/  |_____/       \____/|_|  \__, |     |_____/ \___\__,_|_| |_|
                                               __/ |                             
                                              |___/                              

We made this tool to help cloud security professionals enumerate their [AWS Organizations](https://docs.aws.amazon.com/whitepapers/latest/organizing-your-aws-environment/core-concepts.html) environment looking for potential lateral moves and privilege escalation paths inside the AWS Accounts.

## How it works

Having an initial access to an AWS Account, this tool tries to enumerate the AWS Account to identify new roles and new AWS Accounts.

After the discovery of potential targets, this tool will try to assume each role it acknowledges inside every account. If an AssumeRole succeeds, the tool will recurse to identify a new lateral movement from its new environment.

The tool also relies on the incredible work of **[Rhino Security Labs](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)** to **identify privileges escalation paths** in every AWS account it gets into.

## Security consideration

//!\\\\ This tool perfoms **only read operations**.

**If you customize the code, please make sure you understand what you are doing.**

## Requirements

*  Some valid AWS access keys 

## Usage
One can simply run the script from the command line, and the script will authenticate with the default AWS credentials configured (see **[aws configure](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html)**) :

```bash
user@kali:~/$ git clone "https://github.com/jeff-tch/aws-org-scan.git"
user@kali:~/$ cd aws-org-scan/
user@kali:~/$ pip install -r requirements.txt
user@kali:~/$ python3 ./run.py
```

It is also possible to provide a preferred AWS profile at runtime (see **[auth using env variables](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html)**)  : 

```bash
user@kali:~/$ git clone "https://github.com/jeff-tch/aws-org-scan.git"
user@kali:~/$ cd aws-org-scan/
user@kali:~/$ pip install -r requirements.txt
user@kali:~/$ AWS_PROFILE=your_custom_aws_profile python3 ./run.py
```

Finally, one can also provide his access keys to the script on the command prompt or as arguments :

```bash
user@kali:~/$ git clone "https://github.com/jeff-tch/aws-org-scan.git"
user@kali:~/$ cd aws-org-scan/
user@kali:~/$ pip install -r requirements.txt
user@kali:~/$ [AWS_PROFILE=your_custom_aws_profile] python3 ./run.py --help

usage: run.py [-h] [--access-key-id ACCESS_KEY_ID] [--secret-access-key SECRET_ACCESS_KEY] [--session-token SESSION_TOKEN] [--aws-accounts-list AWS_ACCOUNTS_LIST] [--aws-roles-list AWS_ROLES_LIST] [--log-file LOG_FILE]

This tool was made to help cloud security professionals enumerate their AWS Organizations environment looking for potential lateral moves and privilege escalation paths.

options:
  -h, --help            show this help message and exit
  --access-key-id ACCESS_KEY_ID
                        The AWS access key ID to use for authentication.
  --secret-access-key SECRET_ACCESS_KEY
                        The AWS secret access key to use for authentication.
  --session-token SESSION_TOKEN
                        The AWS session token to use for authentication, if there is one.
  --aws-accounts-list AWS_ACCOUNTS_LIST_FILE
                        A JSON file containing a list of known AWS account IDs.
  --aws-roles-list AWS_ROLES_LIST
                        A JSON file containing a list of known roles.
  --aws-roles-exluded REGEX
                        A REGEX used to exclude several roles from the discovery process.
  --log-file LOG_FILE   The log file.
```
 
## Output
 * This tool displays all its findings on stdout (the screen) during the execution.
 * This tool also saves the lateral moves in a files called by default "*lateral\_movement.log*" (see the option --log-file).
 * This tool also saves the escalation paths in a file named like aws\_privesc\_scan\_results_of\_{AWS-Account-ID}\_by\_{Role-Performing-The-Scan}\_{Timestamp}.csv.

### Example of output (when you have the minimum privileges required ...)

```bash
user@kali:~/$ python3 ./run.py
................. [ -- Output Skipped -- ] .................
Running AWS Escalate from the identity arn:aws:sts::248100021004:assumed-role/role-Random-Role-Name-XYZ012/AssumeRoleSessionName
Collecting policies for 2 users...
  dummyUser... done!
  kakashiSensei... done!
Collecting policies for 17 roles...
  role/AWSReservedSSO_AdministratorAccess_000000000000000... done!
  role/AWSReservedSSO_ReadOnlyAccess_000000000000000... done!
  role/AWSServiceRoleForOrganizations... done!
  role/AWSServiceRoleForSSO... done!
  role/AWSServiceRoleForSupport... done!
  role/AWSServiceRoleForTrustedAdvisor... done!
  role/OrganizationAccountAccessRole... done!
  role/role-Random-Role-Name-XYZ002... done!
  role/role-Random-Role-Name-XYZ010... done!
  role/role-Random-Role-Name-XYZ011... done!
  role/role-Random-Role-Name-XYZ012... done!
  role/role-Random-Role-Name-XYZ013... done!
  role/role-Random-Role-Name-XYZ014... done!
  role/role-Random-Role-Name-XYZ016... done!
  role/role-Random-Role-Name-XYZ018... done!
  role/role-Random-Role-Name-XYZ019... done!
  role/test-role... done!
  Done.

User: dummyUser
  No methods possible.

User: kakashiSensei
  Already an admin!

User: role/AWSReservedSSO_AdministratorAccess_000000000000000
  Already an admin!

User: role/AWSReservedSSO_ReadOnlyAccess_000000000000000
  No methods possible.

User: role/AWSServiceRoleForOrganizations
  No methods possible.

User: role/AWSServiceRoleForSSO
  No methods possible.

User: role/AWSServiceRoleForSupport
  No methods possible.

User: role/AWSServiceRoleForTrustedAdvisor
  No methods possible.

User: role/OrganizationAccountAccessRole
  Already an admin!

User: role/role-Random-Role-Name-XYZ002
  No methods possible.

User: role/role-Random-Role-Name-XYZ010
  POTENTIAL: AttachRolePolicy

User: role/role-Random-Role-Name-XYZ011
  POTENTIAL: UpdateRolePolicyToAssumeIt

User: role/role-Random-Role-Name-XYZ012
  CONFIRMED: PassExistingRoleToNewLambdaThenInvoke

  CONFIRMED: EditExistingLambdaFunctionWithRole

User: role/role-Random-Role-Name-XYZ013
  CONFIRMED: PassExistingRoleToNewGlueDevEndpoint

  CONFIRMED: UpdateExistingGlueDevEndpoint

User: role/role-Random-Role-Name-XYZ014
  CONFIRMED: PassExistingRoleToCloudFormation

User: role/role-Random-Role-Name-XYZ016
  CONFIRMED: CreateNewPolicyVersion

User: role/role-Random-Role-Name-XYZ018
  No methods possible.

User: role/role-Random-Role-Name-XYZ019
  No methods possible.

User: role/test-role
  Already an admin!

Privilege escalation check completed. Results stored to ./aws_privesc_scan_results_of_248100021004_by_assumed-role_role-Random-Role-Name-XYZ012_AssumeRoleSessionName_1692687071.8171043.csv
Discovered new role :: role-Random-Role-Name-XYZ020
Discovered new role :: role-Random-Role-Name-XYZ003
Discovered new role :: aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_000000000000000
Discovered new role :: role-Random-Role-Name-XYZ016
Discovered new role :: aws-reserved/sso.amazonaws.com/AWSReservedSSO_ReadOnlyAccess_000000000000000
Discovered new role :: role-Random-Role-Name-XYZ019
Discovered new role :: role-Random-Role-Name-XYZ015
Assume role found | 55320000001::role-Random-Role-Name-XYZ009 --> 248100021004::role-Random-Role-Name-XYZ012
---------------------------------------------------------------------
Running AWS Escalate from the identity arn:aws:sts::976030000038:assumed-role/role-Random-Role-Name-XYZ015/AssumeRoleSessionName
Assume role found | 248100021004::role-Random-Role-Name-XYZ012 --> 976030000038::role-Random-Role-Name-XYZ015
---------------------------------------------------------------------
Running AWS Escalate from the identity arn:aws:sts::248100021004:assumed-role/role-Random-Role-Name-XYZ016/AssumeRoleSessionName
Assume role found | 976030000038::role-Random-Role-Name-XYZ015 --> 248100021004::role-Random-Role-Name-XYZ016
---------------------------------------------------------------------
Running AWS Escalate from the identity arn:aws:sts::55320000001:assumed-role/role-Random-Role-Name-XYZ017/AssumeRoleSessionName
Assume role found | 976030000038::role-Random-Role-Name-XYZ015 --> 55320000001::role-Random-Role-Name-XYZ017
---------------------------------------------------------------------
Running AWS Escalate from the identity arn:aws:sts::248100021004:assumed-role/role-Random-Role-Name-XYZ018/AssumeRoleSessionName
Assume role found | 55320000001::role-Random-Role-Name-XYZ017 --> 248100021004::role-Random-Role-Name-XYZ018
---------------------------------------------------------------------
Running AWS Escalate from the identity arn:aws:sts::248100021004:assumed-role/role-Random-Role-Name-XYZ019/AssumeRoleSessionName
Assume role found | 248100021004::role-Random-Role-Name-XYZ018 --> 248100021004::role-Random-Role-Name-XYZ019
................. [ -- Output Skipped -- ] .................
```
## TODO
 * Implement a nice output (JSON/CSV/Excel/Graph/... anything better than raw text).
 * Implement a way to query which role/account can access which role/account. (Probably requires to first dump the output in a structured way (json/table/...))
 * Document the set of AWS Permissions this tool requires to see everything.
 * Document the minimum set of AWS Permissions required by this tool.
