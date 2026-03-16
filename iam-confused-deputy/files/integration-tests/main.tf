############ Local variables ############

locals {
  description = ""
  name_prefix = "config-iam-confused-deputy-test"
}

############ Data Sources ############

data "aws_caller_identity" "this" {}

############ Naming ############

resource "random_string" "this" {
  keepers = {
    name = local.name_prefix
  }
  length  = 8
  special = false
}

############ COMPLIANT IAM role ############

data "aws_iam_policy_document" "compliant_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values = [
        data.aws_caller_identity.this.account_id
      ]
    }
  }
}

resource "aws_iam_role" "compliant" {
  assume_role_policy = data.aws_iam_policy_document.compliant_assume_role.json
  name               = "${local.name_prefix}-compliant-${random_string.this.id}"
}

############ NON_COMPLIANT IAM role ############

data "aws_iam_policy_document" "non_compliant_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "non_compliant" {
  assume_role_policy = data.aws_iam_policy_document.non_compliant_assume_role.json
  name               = "${local.name_prefix}-non_compliant-${random_string.this.id}"
}

############ NOT_APPLICABLE IAM role ############

data "aws_iam_policy_document" "not_applicable_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [data.aws_caller_identity.this.arn]
    }
  }
}

resource "aws_iam_role" "not_applicable" {
  assume_role_policy = data.aws_iam_policy_document.not_applicable_assume_role.json
  name               = "${local.name_prefix}-not_applicable-${random_string.this.id}"
}
