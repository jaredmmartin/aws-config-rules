# iam-confused-deputy

## Overview

Custom AWS Config rule to evaluate whether IAM role trust policies implement protections for the [confused deputy problem](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html). The compliance evaluation is triggered when an IAM role is changed. The Config rule only applies to IAM roles where the trust policy allows an AWS service principal (e.g. `lambda.amazonaws.com`). If the trust policy allows any other type of principal (e.g. another IAM role), the compliance decision is `NOT_APPLICABLE`. If the trust policies allows an AWS service principal to assume the role, the evaluation will parse the trust policy to determine if each statement contains a condition that implements protection from the confused deputy problem. The condition element must contain at least one of the following keys:

+ `aws:PrincipalAccount`
+ `aws:PrincipalArn`
+ `aws:PrincipalOrgID`
+ `aws:PrincipalOrgPaths`
+ `aws: SourceAccount`
+ `aws: SourceArn`
+ `aws: SourceOrgID`
+ `aws: SourceOrgPaths`
+ `sts:ExternalId`

If at least one of the required keys is present in all statements that allow an AWS service principal to assume the role, the compliance decision is `COMPLIANT`. Otherwise, the compliance decision is `NON_COMPLIANT`.

### Unit tests

The `files/tests/` directory contains unit tests for the custom AWS Config rule Lambda function. The unit tests validate error handling and compliance evaluation logic of the Lambda function python script.

Unit tests:

+ `test_compliant_when_condition_with multi_required_key`: Test to validate that IAM role trust policy with one statement containing condition with multiple required keys evaluates to `COMPLIANT`
+ `test_compliant_when_condition_with_multi_key_one_required`: Test to validate that IAM role trust policy with one statement containing condition with one of the required keys evaluates to `COMPLIANT`
+ `test_compliant_when_condition_with_required_key`: Test to validate that IAM role trust policy with one statement containing condition with one required key evaluates to `COMPLIANT`
+ `test_compliant_when_statement_with_condition_with_required_key_and_statement_with_deny_effect`: Test to validate that IAM role trust policy with one statement containing condition with required key and one statement with deny effect evaluates to `COMPLIANT`
+ `test_compliant_when_statement_with_condition_with_required_key_and_statement_with_other_principal`: Test to validate that IAM role trust policy with one statement containing condition with required key and one statement allowing non-service principal evaluates to `COMPLIANT`
+ `test_error_on_invalid_policy_document`: Test to validate that invalid IAM role trust policy throws error
+ `test_non_compliant_when_condition_with_other_key multi_value`: Test to validate that IAM role trust policy with one statement containing condition with multiple keys that are not in the list of required keys evaluates to `NON_COMPLIANT`
+ `test_non_compliant_when_condition_with_other_key`: Test to validate that IAM role trust policy with one statement containing condition with key that is not in the list of required keys evaluates to `NON_COMPLIANT`
+ `test_non_compliant_when_multi_statement_with_and without_condition`: Test to validate that IAM role trust policy with one statement containing condition with required key and one statement without condition evaluates to `NON_COMPLIANT`
+ `test_non_compliant_when_service_principal_without_condition`: Test to validate that IAM trust policy with one statement without condition element evaluates to `NON_COMPLIANT`
+ `test_non_deleted_resource_is_evaluated`: Test to validate that non-deleted IAM role is evaluated
+ `test_not_applicable_when_aws_managed_path_multi_statement`: Test to validate that IAM role in AWS-managed paths with trust policy containing multiple statements evaluates to `NOT_APPLICABLE`
+ `test_not_applicable_when_aws_managed_path`: Test to validate that IAM role in AWS-managed paths evaluates to `NOT_APPLICABLE`
+ `test_not_applicable_when_deleted_resource`: Test to validate that deleted IAM role is not evaluated

## Requirements

+ Python 3.13
+ Python modules
  + `boto3`
  + `pytest`
+ Terraform 1.6.0+
+ Terraform providers
  + `hashicorp/aws`

## Usage

The Config rule evaluation is triggered by changes to IAM roles. The compliance evaluations can be reviewed in the AWS Config console. Logs of the Lambda function that performs the compliance evaluation are output to the CloudWatch log group `/aws/config-iam-confused-deputy`.

To run the unit tests:

```shell
# Set working directory
cd "iam-confused-deputy"

# Create and activate virtual env
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
cd "iam-confused-deputy"

# Initialize Terraform
terraform init

# Provision
terraform apply
```

## Troubleshooting

Review the Lambda function logs in the CloudWatch log group `/aws/config-iam-confused-deputy`.

## Useful documentation

[The confused deputy problem | AWS Identity and Access Management](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html).

[Supported Resource Types for AWS Config | AWS Config](https://docs.aws.amazon.com/config/latest/developerguide/resource-config-reference.html)
