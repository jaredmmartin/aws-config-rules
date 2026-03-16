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
# Set working directory
cd "sns-email-subscription-domain"

# Create virtual env
python3 -m venv venv
source venv/bin/activate

# Install requirements
pip install boto3 pytest

# Set the working directory
cd "files"

# Run the tests
python -m pytest -rA

# Exit the virtual env
deactivate
```

## Deployment

To deploy the Config rule:

```shell
# Set environment variables, if necessary
export AWS_ACCESS_KEY_ID=""
export AWS_SECRET_ACCESS_KEY=""

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
