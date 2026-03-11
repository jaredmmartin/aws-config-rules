# sns-email-subscription-domain

## Overview

Custom AWS Config rule to evaluate whether SNS topic email subscriptions use email addresses from approved domains.

### Unit tests



## Requirements

+ Python 3.13
+ Python modules
  + `boto3`
  + `pytest`
+ Terraform 1.6.0+
+ Terraform providers
  + `hashicorp/aws`

## Usage

The Config rule evaluation is triggered on a recurring schedule. The compliance evaluations can be reviewed in the AWS Config console. Logs of the Lambda function that performs the compliance evaluation are output to the CloudWatch log group `/aws/config-sns-email-subscription-domain`.

To run the unit tests:

```shell
# Create virtual env
python3 -m venv venv

# Activate virtual env
source venv/bin/activate

# Set the working directory
cd "sns-email-subscription-domain/files"

# Run the tests
python -m pytest -rA
```

## Deployment

To deploy the Config rule:

```shell
# Set environment variables, if necessary
export AWS_ACCESS_KEY_ID=""
export AWS_SECRET_ACCESS_KEY=""
export AWS_SESSION_TOKEN=""

# Set the working directory
cd "sns-email-subscription-domain"

# Initialize Terraform
terraform init

# Provision
terraform apply
```

## Troubleshooting

Review the Lambda function logs in the CloudWatch log group `/aws/config-sns-email-subscription-domain`.

## Useful documentation

[Supported Resource Types for AWS Config](https://docs.aws.amazon.com/config/latest/developerguide/resource-config-reference.html)

[SNS - Boto3 documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sns.html)
