############ Local variables ############

locals {
  name_prefix = "config-recorder"
}

############ Data Sources ############

data "aws_caller_identity" "this" {}

data "aws_iam_policy" "config" {
  name = "AWSConfigRulesExecutionRole"
}

data "aws_iam_policy" "lambda" {
  name = "AWSLambdaBasicExecutionRole"
}

data "aws_region" "this" {}

############ Naming ############

resource "random_string" "this" {
  keepers = {
    name = local.name_prefix
  }
  length  = 8
  special = false
}

############ S3 ############

resource "aws_s3_bucket" "this" {
  bucket        = "${local.name_prefix}-${random_string.this.id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "this" {
  block_public_acls       = true
  block_public_policy     = true
  bucket                  = aws_s3_bucket.this.id
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "this" {
  statement {
    sid     = "BucketPermissionsCheck"
    actions = ["s3:GetBucketAcl"]
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    resources = [aws_s3_bucket.this.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.this.account_id]
    }
  }
  statement {
    sid     = "BucketExistenceCheck"
    actions = ["s3:ListBucket"]
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    resources = [aws_s3_bucket.this.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.this.account_id]
    }
  }
  statement {
    sid     = "BucketDelivery"
    actions = ["s3:PutObject"]
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    resources = ["${aws_s3_bucket.this.arn}/AWSLogs/${data.aws_caller_identity.this.account_id}/Config/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.this.account_id]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.this.id
  policy = data.aws_iam_policy_document.this.json
}

############ IAM ############

resource "aws_iam_service_linked_role" "this" {
  aws_service_name = "config.amazonaws.com"
}

############ Config ############

resource "aws_config_configuration_recorder" "this" {
  name     = "${local.name_prefix}-${random_string.this.id}"
  role_arn = aws_iam_service_linked_role.this.arn
}

resource "aws_config_delivery_channel" "this" {
  depends_on = [aws_config_configuration_recorder.this]

  name           = "${local.name_prefix}-${random_string.this.id}"
  s3_bucket_name = aws_s3_bucket.this.bucket
}

resource "aws_config_configuration_recorder_status" "this" {
  depends_on = [aws_config_delivery_channel.this]

  is_enabled = true
  name       = aws_config_configuration_recorder.this.name
}

resource "aws_config_retention_configuration" "this" {
  retention_period_in_days = 30
}
