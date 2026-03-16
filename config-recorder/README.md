# config-recorder

## Overview

Terraform configuration to setup AWS Config with a configuration recorder with 30 day retention, delivery channel to store Config data in a S3 bucket, and enables the configuration recorder.

The Terraform configuration creates the following resources:

+ AWS IAM service-linked role for Config
+ AWS S3 bucket for configuration recorder
+ AWS Config configuration recorder for all resource types
+ AWS Config delivery channel to store configuration item data in S3 bucket
+ AWS Config retention policy to store configuration item data for 30 days

## Requirements

+ Terraform 1.6.0+
+ Terraform providers
  + `hashicorp/aws`

## Usage

To deploy:

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
