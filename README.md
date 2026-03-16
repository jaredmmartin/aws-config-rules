# aws-config-rules

A collection of AWS Config custom rules with Lambda functions written in Python and Terraform deployment.

## Contents

### config-recorder

Terraform configuration to setup AWS Config. The AWS Config recorder must be deployed before the custom AWS Config rules will function.

### Custom AWS Config rules

#### ec2-image-lineage

Terraform configuration to deploy AWS Config custom rule that assesses compliance of EC2 instance image lineage to approved image owners.

#### iam-confused-deputy

Terraform configuration to deploy AWS Config custom rule that assesses compliance of IAM roles for confused deputy protections.

#### sns-email-subscription-domain

Terraform configuration to deploy AWS Config custom rule that assesses compliance of SNS topic email subscriptions from approved domain list.
