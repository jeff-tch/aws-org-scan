
# IAM - AWS Organizations Scanner 

         __          _______        ____                   _____                 
        /\ \        / / ____|      / __ \                 / ____|                
       /  \ \  /\  / / (___ ______| |  | |_ __ __ _ _____| (___   ___ __ _ _ __  
      / /\ \ \/  \/ / \___ \______| |  | | '__/ _` |______\___ \ / __/ _` | '_ \ 
     / ____ \  /\  /  ____) |     | |__| | | | (_| |      ____) | (_| (_| | | | |
    /_/    \_\/  \/  |_____/       \____/|_|  \__, |     |_____/ \___\__,_|_| |_|
                                               __/ |                             
                                              |___/                              

We made this tool to help cloud security professionals enumerate their AWS Organizations environment looking for potential lateral moves and privilege escalation paths.

## How it works

Having an initial access to an AWS Account, this tool to try to enumerate the AWS Account to identify new roles and new AWS Accounts.

After the discovery of potential targets, this tool will try to assume each role he acknowledges inside every account. If an AssumeRole succeeds, the tool will recurse to identify a new lateral movement from his new environment.

The tool also relies on the incredible work of **[Rhino Security Labs](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)** to **identify privileges escalation paths** in every AWS account it gets into which each role.

## Requirements

*  Some valid AWS access keys 

## Usage
One can simple run the script from the command line, and the script will authenticate with the default AWS credentials configured (see [aws configure]()) :

```bash
user@kali:~/$ python3 ./run.py
```

It is also possible to provide a preferred AWS profile at runtime : 

```bash
user@kali:~/$ AWS_PROFILE=your_custom_aws_profile python3 ./run.py
```

Finally, one can provide his access keys to the script on the command prompt or as arguments :

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
  --aws-accounts-list AWS_ACCOUNTS_LIST
                        A JSON file containing a list of known AWS account IDs.
  --aws-roles-list AWS_ROLES_LIST
                        A JSON file containing a list of known roles.
  --log-file LOG_FILE   The log file.
```
## TODO
 * Implement a nice output (JSON/CSV/Excel/Graph/... anything better that raw text).
 * ...
