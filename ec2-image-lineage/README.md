# ec2-image-lineage

## Overview

Custom AWS Config rule to evaluate EC2 instances to determine whether each image in the lineage is approved. The compliance evaluation is triggered when an EC2 instance is changed. The compliance evaluation examines the EC2 instance image to determine if the image is approved by the explicit image ID, owned by current AWS account ID, owned by an approved AWS account ID, or owned by an approved AWS account alias. If the EC2 image was created from another EC2 image, the source EC2 image is also evaluated. The evaluation repeats until all EC2 images in the lineage have been evaluated. If all EC2 images in the lineage are approved, the compliance decision is `COMPLIANT`. If any EC2 image in the lineage is not approved, the compliance decision is `NON_COMPLIANT`.

The Terraform configuration contains three parameters for the Config rule that can be used to specify EC2 image approval by image ID, owner AWS account ID, or owner AWS account alias:

+ `APPROVED_IMAGE_IDS`: Used to approve EC2 images by explicit image ID
+ `APPROVED_IMAGE_OWNER_ALIASES`: Used to approve images by owner AWS account aliases. Includes `amazon` by default.
+ `APPROVED_IMAGE_OWNER_IDS`: Used to approve images by owner AWS account IDs

## Requirements

+ Python 3.13
+ Python modules
  + `boto3`
  + `tabulate`
+ Terraform 1.6.0+
+ Terraform providers
  + `hashicorp/aws`

## Usage

The Config rule evaluation is triggered by changes to EC2 instances. The compliance evaluations can be reviewed in the AWS Config console. Logs of the Lambda function that performs the compliance evaluation are output to the CloudWatch log group `/aws/config-ec2-image-lineage`.

## Deployment

To deploy the Config rule:

```shell
# Set environment variables, if necessary
export AWS_ACCESS_KEY_ID=""
export AWS_SECRET_ACCESS_KEY=""

# Set the working directory
cd "ec2-image-lineage"

# Initialize Terraform
terraform init

# Provision
terraform apply
```

## Troubleshooting

Review the Lambda function logs in the CloudWatch log group `/aws/config-ec2-image-lineage`.

## Useful documentation

[Use AMI ancestry to trade the origin of an AMI | AWS Elastic Compute Cloud](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ami-ancestry.html#identify-source-ami-used-to-create-new-ami)

[Supported Resource Types for AWS Config | AWS Config](https://docs.aws.amazon.com/config/latest/developerguide/resource-config-reference.html)
