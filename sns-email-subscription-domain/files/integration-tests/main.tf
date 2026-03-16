############ Local variables ############

locals {
  description = ""
  name_prefix = "config-sns-email-subscription-domain-test"
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

############ COMPLIANT SNS Subscription ############


############ NON_COMPLIANT SNS Subscription ############


############ NOT_APPLICABLE SNS Subscription ############

