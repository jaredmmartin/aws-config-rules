from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch
import json
import logging
import pytest
import re
import urllib.parse

# Import the functions to test
from lambda_function import evaluate_compliance
from lambda_function import lambda_handler


###### Logging setup ######

# Set the project directory
current_dir = Path(__file__).resolve().parent

# Set the log directory path
log_dir = current_dir / "logs"

# Create the logs directory if it doesn't exist
log_dir.mkdir(parents=True, exist_ok=True)

# Set a variable for the entry format
log_format = "[%(asctime)s] [%(levelname)s] %(message)s"

# Configure logging to file
logging.basicConfig(
    filename=str(log_dir / f"{datetime.now().isoformat()}.log"),
    format=log_format,
)
console_log = logging.StreamHandler()
console_log.setFormatter(logging.Formatter(fmt=log_format))

# Configure logging to console
log = logging.getLogger(Path(__file__).stem)
log.addHandler(console_log)

# Configure log level
log.setLevel(logging.DEBUG)

###### Helper functions ######


def encode_policy_document(policy_dict: dict) -> str:
    """
    Helper to URL-encode an assume role policy document.
    """

    return urllib.parse.quote_plus(json.dumps(policy_dict))


@pytest.fixture
def invoking_event():
    return {
        "configurationItem": {
            "configuration": {
                "assumeRolePolicyDocument": "",
                "path": "/",
                "roleName": "test-role",
            }
        }
    }


@pytest.fixture
def rule_parameters():
    return {
        "required_condition_keys": [
            "aws:PrincipalAccount",
            "aws:PrincipalArn",
            "aws:PrincipalOrgID",
            "aws:PrincipalOrgPaths",
            "aws:SourceAccount",
            "aws:SourceArn",
            "aws:SourceOrgID",
            "aws:SourceOrgPaths",
            "sts:ExternalId",
        ]
    }


@pytest.fixture
def mock_evaluate_compliance():
    with patch("lambda_function.evaluate_compliance") as mock_eval:
        mock_eval.return_value = (
            "COMPLIANT",
            "Statement condition contains aws:SourceAccount key(s).",
        )
        yield mock_eval


@pytest.fixture
def event():
    return {
        "invokingEvent": json.dumps(
            {
                "configurationItem": {
                    "resourceType": "AWS::IAM::Role",
                    "awsAccountId": "123456789012",
                    "resourceId": "test-role",
                    "configurationItemStatus": "OK",
                    "configurationItemCaptureTime": "2025-01-01T00:00:00.000Z",
                }
            }
        ),
        "ruleParameters": json.dumps(
            {
                "remote_iam_role_name": "test-remote-role",
                "required_condition_keys": [
                    "aws:PrincipalAccount",
                    "aws:PrincipalArn",
                    "aws:PrincipalOrgID",
                    "aws:PrincipalOrgPaths",
                    "aws:SourceAccount",
                    "aws:SourceArn",
                    "aws:SourceOrgID",
                    "aws:SourceOrgPaths",
                    "sts:ExternalId",
                ],
            }
        ),
        "resultToken": "1234567890abcdefghijklmnopqrstuvwxyz",
    }


@pytest.fixture
def mock_boto_clients():
    """
    Patch boto3 client so we can control STS and Config-
    Returns tuple (mock_sts_client, mock_config_client).
    """
    with patch("lambda_function.boto3.client") as mock_client:
        # STS client
        mock_sts = MagicMock()
        mock_sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "AKIA_TEST",
                "SecretAccessKey": "SECRET_TEST",
                "SessionToken": "TOKEN_TEST",
            }
        }

        # Config client
        mock_config = MagicMock()

        # boto3 client side effects: first call 'sts', second call 'config'
        def client_side_effect(service_name, *args, **kwargs):
            if service_name == "sts":
                return mock_sts
            elif service_name == "config":
                return mock_config
            else:
                raise ValueError(f"Unexpected service: {service_name}")

        mock_client.side_effect = client_side_effect

        yield mock_sts, mock_config


###### Lambda Handler tests ######


def test_not_applicable_when_deleted_resource(
    event, mock_boto_clients, mock_evaluate_compliance
):
    # Create the AWS clients
    config_client = mock_boto_clients

    # Create the invocation event
    invoking = json.loads(event["invokingEvent"])

    # Set the configuration item status to indicate the resource is deleted
    invoking["configurationItem"]["configurationItemStatus"] = "ResourceDeleted"

    # Convert the invocation event to JSON
    event["invokingEvent"] = json.dumps(invoking)

    # Invoke the function
    lambda_handler(event, context=None)

    # evaluate_compliance should not be called
    mock_evaluate_compliance.assert_not_called()

    # put_evaluations should be called
    config_client.put_evaluations.assert_called_once()

    # Set a variable for the parameters of the put_evaluations call
    call_kwargs = config_client.put_evaluations.call_args.kwargs

    # The ResultToken parameter should be the same value as the invocation event
    assert call_kwargs["ResultToken"] == event["resultToken"]

    # Set a variable for the Evaluations parameter
    evaluations = call_kwargs["Evaluations"]

    # The Evaluations parameter should have exactly one item
    assert len(evaluations) == 1

    # The evaluation ComplianceType should be NOT_APPLICABLE
    assert evaluations[0]["ComplianceType"] == "NOT_APPLICABLE"

    # The evaluation ComplianceResourceType should be an IAM role
    assert evaluations[0]["ComplianceResourceType"] == "AWS::IAM::Role"

    # The evaluation ComplianceResourceId should be test-role
    assert evaluations[0]["ComplianceResourceId"] == "test-role"


def test_non_deleted_resource_is_evaluated(
    event, mock_boto_clients, mock_evaluate_compliance
):
    # Create the AWS clients
    config_client = mock_boto_clients

    # configurationItemStatus is OK by default in the base event fixture
    lambda_handler(event, context=None)

    # Set a variable for the invocation event
    invoking_event = json.loads(event["invokingEvent"])

    # Set a variable for the rule parameters
    rule_parameters = json.loads(event["ruleParameters"])

    # evaluate_compliance should be called with specified parameters
    mock_evaluate_compliance.assert_called_once_with(
        invoking_event=invoking_event, rule_parameters=rule_parameters
    )

    # put_evaluations should be called
    config_client.put_evaluations.assert_called_once()

    # Set a variable for the parameters of the put_evaluations call
    call_kwargs = config_client.put_evaluations.call_args.kwargs

    # The ResultToken parameter should be the same value as the invocation event
    assert call_kwargs["ResultToken"] == event["resultToken"]

    # Set a variable for the Evaluations parameter
    evaluations = call_kwargs["Evaluations"]

    # The Evaluations parameter should have exactly one item
    assert len(evaluations) == 1

    # The evaluation ComplianceType should be COMPLIANT
    assert evaluations[0]["ComplianceType"] == "COMPLIANT"

    # The evaluation ComplianceResourceType should be an IAM role
    assert evaluations[0]["ComplianceResourceType"] == "AWS::IAM::Role"

    # The evaluation ComplianceResourceId should be test-role
    assert evaluations[0]["ComplianceResourceId"] == "test-role"


###### evaluate_compliance tests ######


def test_error_on_invalid_policy_document(invoking_event, rule_parameters):
    # evaluate_compliance should raise an exception
    with pytest.raises(Exception):
        # Create invalid assume role policy document for the test case
        assume_role_policy_document = urllib.parse.quote_plus("%%%INVALID%%%")

        # Create invocation event
        event = {
            "configurationItem": {
                "configuration": {
                    "assumeRolePolicyDocument": assume_role_policy_document,
                    "path": "/",
                    "roleName": "test-role",
                },
            },
        }

        # Perform the compliance evaluation
        compliance_decision, compliance_annotations = evaluate_compliance(
            invoking_event=invoking_event, rule_parameters=rule_parameters
        )


def test_not_applicable_when_aws_managed_path(invoking_event, rule_parameters):
    # Set IAM role path to AWS service-managed IAM role path
    invoking_event["configurationItem"]["configuration"]["path"] = "/aws-service-role/"

    # Perform the compliance evaluation
    compliance_decision, compliance_annotations = evaluate_compliance(
        invoking_event=invoking_event, rule_parameters=rule_parameters
    )

    # Assert the expected compliance decision
    assert compliance_decision == "NOT_APPLICABLE"


def test_not_applicable_when_aws_managed_path_multi_statement(
    invoking_event, rule_parameters
):
    # Set assume role trust policy
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            },
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            },
        ],
    }

    # Set the policy document
    invoking_event["configurationItem"]["configuration"]["assumeRolePolicyDocument"] = (
        encode_policy_document(policy)
    )

    # Set the role path
    invoking_event["configurationItem"]["configuration"]["path"] = "/aws-service-role/"

    # Perform the compliance evaluation
    compliance_decision, compliance_annotations = evaluate_compliance(
        invoking_event=invoking_event, rule_parameters=rule_parameters
    )

    # Assert the expected compliance decision
    assert compliance_decision == "NOT_APPLICABLE"


def test_not_not_applicable_when_non_default_path(invoking_event, rule_parameters):
    # Set assume role trust policy
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            },
        ],
    }

    # Set the policy document
    invoking_event["configurationItem"]["configuration"]["assumeRolePolicyDocument"] = (
        encode_policy_document(policy)
    )

    # Perform the compliance evaluation
    compliance_decision, compliance_annotations = evaluate_compliance(
        invoking_event=invoking_event, rule_parameters=rule_parameters
    )

    # Assert the expected compliance decision
    assert compliance_decision != "NOT_APPLICABLE"


def test_not_applicable_when_deny_effect(invoking_event, rule_parameters):
    # Set assume role trust policy
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            },
        ],
    }

    # Set the policy document
    invoking_event["configurationItem"]["configuration"]["assumeRolePolicyDocument"] = (
        encode_policy_document(policy)
    )

    # Perform the compliance evaluation
    compliance_decision, compliance_annotations = evaluate_compliance(
        invoking_event=invoking_event, rule_parameters=rule_parameters
    )

    # Assert the expected compliance decision
    assert compliance_decision == "NOT_APPLICABLE"


def test_not_applicable_when_non_service_principal(invoking_event, rule_parameters):
    # Set assume role trust policy
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }

    # Set the policy document
    invoking_event["configurationItem"]["configuration"]["assumeRolePolicyDocument"] = (
        encode_policy_document(policy)
    )

    # Perform the compliance evaluation
    compliance_decision, compliance_annotations = evaluate_compliance(
        invoking_event=invoking_event, rule_parameters=rule_parameters
    )

    # Assert the expected compliance decision
    assert compliance_decision == "NOT_APPLICABLE"


def test_not_applicable_when_non_service_principal_with_condition(
    invoking_event, rule_parameters
):
    # Set assume role trust policy
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Principal": {"AWS": "arn:aws:iam::123456789012:role/test-role"},
                "Condition": {
                    "StringEquals": {
                        "sts:ExternalId": "1234567890abcdefghijklmnopqrstuvwxyz",
                    },
                },
            },
        ],
    }

    # Set the policy document
    invoking_event["configurationItem"]["configuration"]["assumeRolePolicyDocument"] = (
        encode_policy_document(policy)
    )

    # Perform the compliance evaluation
    compliance_decision, compliance_annotations = evaluate_compliance(
        invoking_event=invoking_event, rule_parameters=rule_parameters
    )

    # Assert the expected compliance decision
    assert compliance_decision == "NOT_APPLICABLE"


def test_non_compliant_when_service_principal_without_condition(
    invoking_event, rule_parameters
):
    # Set assume role trust policy
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            },
        ],
    }

    # Set the policy document
    invoking_event["configurationItem"]["configuration"]["assumeRolePolicyDocument"] = (
        encode_policy_document(policy)
    )

    # Perform the compliance evaluation
    compliance_decision, compliance_annotations = evaluate_compliance(
        invoking_event=invoking_event, rule_parameters=rule_parameters
    )

    # Assert the expected compliance decision
    assert compliance_decision == "NON_COMPLIANT"


def test_non_compliant_when_multi_statement_with_and_without_condition(
    invoking_event, rule_parameters
):
    # Set assume role trust policy
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "drs.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:SetSourceIdentity"],
                "Condition": {
                    "StringLike": {"aws:SourceAccount": "123456789012"},
                },
            },
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:SetSourceIdentity"],
            },
        ],
    }

    # Set the policy document
    invoking_event["configurationItem"]["configuration"]["assumeRolePolicyDocument"] = (
        encode_policy_document(policy)
    )

    # Perform the compliance evaluation
    compliance_decision, compliance_annotations = evaluate_compliance(
        invoking_event=invoking_event, rule_parameters=rule_parameters
    )

    # Assert the expected compliance decision
    assert compliance_decision == "NON_COMPLIANT"


def test_non_compliant_when_condition_with_other_key(invoking_event, rule_parameters):
    # Set assume role trust policy
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:CalledVia": "s3.amazonaws.com"}},
            },
        ],
    }

    # Set the policy document
    invoking_event["configurationItem"]["configuration"]["assumeRolePolicyDocument"] = (
        encode_policy_document(policy)
    )

    # Perform the compliance evaluation
    compliance_decision, compliance_annotations = evaluate_compliance(
        invoking_event=invoking_event, rule_parameters=rule_parameters
    )

    # Assert the expected compliance decision
    assert compliance_decision == "NON_COMPLIANT"


def test_non_compliant_when_condition_with_other_key_multi_value(
    invoking_event, rule_parameters
):
    # Set assume role trust policy
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Condition": {
                    "IpAddress": {
                        "aws:SourceIp": [
                            "172.16.0.0/24",
                            "172.16.1.0/24",
                            "172.30.0.0/24",
                            "172.31.0.0/24",
                        ],
                    },
                },
            },
        ],
    }

    # Set the policy document
    invoking_event["configurationItem"]["configuration"]["assumeRolePolicyDocument"] = (
        encode_policy_document(policy)
    )

    # Perform the compliance evaluation
    compliance_decision, compliance_annotations = evaluate_compliance(
        invoking_event=invoking_event, rule_parameters=rule_parameters
    )

    # Assert the expected compliance decision
    assert compliance_decision == "NON_COMPLIANT"


def test_compliant_when_condition_with_required_key(invoking_event, rule_parameters):
    # Set assume role trust policy
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceAccount": "123456789012"}},
            },
        ],
    }

    # Set the policy document
    invoking_event["configurationItem"]["configuration"]["assumeRolePolicyDocument"] = (
        encode_policy_document(policy)
    )

    # Perform the compliance evaluation
    compliance_decision, compliance_annotations = evaluate_compliance(
        invoking_event=invoking_event, rule_parameters=rule_parameters
    )

    # Assert the expected compliance decision
    assert compliance_decision == "COMPLIANT"


def test_compliant_when_condition_with_multi_required_key(
    invoking_event, rule_parameters
):
    # Set assume role trust policy
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "drs.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:SetSourceldentity"],
                "Condition": {
                    "StringLike": {
                        "aws:SourceAccount": "123456789012",
                        "sts:SourceIdentity": "i-*",
                    },
                },
            },
        ],
    }

    # Set the policy document
    invoking_event["configurationItem"]["configuration"]["assumeRolePolicyDocument"] = (
        encode_policy_document(policy)
    )

    # Perform the compliance evaluation
    compliance_decision, compliance_annotations = evaluate_compliance(
        invoking_event=invoking_event, rule_parameters=rule_parameters
    )

    # Assert the expected compliance decision
    assert compliance_decision == "COMPLIANT"


def test_compliant_when_condition_with_multi_key_one_required(
    invoking_event, rule_parameters
):
    # Create the assume role policy document for the test case
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "drs.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:SetSourceIdentity"],
                "Condition": {
                    "StringLike": {
                        "aws:SourceAccount": "123456789012",
                        "aws:SourceVpce": "vpce-1234567890abcdefg",
                    },
                },
            },
        ],
    }

    # Set the policy document
    invoking_event["configurationItem"]["configuration"]["assumeRolePolicyDocument"] = (
        encode_policy_document(policy)
    )

    # Perform the compliance evaluation
    compliance_decision, compliance_annotations = evaluate_compliance(
        invoking_event=invoking_event, rule_parameters=rule_parameters
    )

    # Assert the expected compliance decision
    assert compliance_decision == "COMPLIANT"


def test_compliant_when_statement_with_condition_with_required_key_and_statement_with_other_principal(
    invoking_event, rule_parameters
):
    # Set assume role trust policy
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "drs.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:SetSourceIdentity"],
                "Condition": {
                    "StringLike": {
                        "aws:SourceAccount": "123456789012",
                        "aws:SourceVpce": "vpce-123456789@abcdefg",
                    },
                },
            },
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:role/test-role"},
                "Action": ["sts:AssumeRole", "sts:SetSourceIdentity"],
            },
        ],
    }

    # Set the policy document
    invoking_event["configurationItem"]["configuration"]["assumeRolePolicyDocument"] = (
        encode_policy_document(policy)
    )

    # Perform the compliance evaluation
    compliance_decision, compliance_annotations = evaluate_compliance(
        invoking_event=invoking_event, rule_parameters=rule_parameters
    )

    # Assert the expected compliance decision
    assert compliance_decision == "COMPLIANT"


def test_compliant_when_statement_with_condition_with_required_key_and_statement_with_deny_effect(
    invoking_event, rule_parameters
):
    # Set assume role trust policy
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "drs.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:SetSourceIdentity"],
                "Condition": {
                    "StringLike": {
                        "aws:SourceAccount": "123456789012",
                        "aws:SourceVpce": "vpce-1234567890abcdefg",
                    },
                },
            },
            {
                "Effect": "Deny",
                "Principal": {"Service": "drs.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:SetSourceIdentity"],
                "Condition": {
                    "NotIpAddress": {
                        "aws:SourceIp": [
                            "172.16.0.0/24",
                            "172.16.1.0/24",
                            "172.30.0.0/24",
                            "172.31.0.0/24",
                        ],
                    },
                },
            },
        ],
    }

    # Set the policy document
    invoking_event["configurationItem"]["configuration"]["assumeRolePolicyDocument"] = (
        encode_policy_document(policy)
    )

    # Perform the compliance evaluation
    compliance_decision, compliance_annotations = evaluate_compliance(
        invoking_event=invoking_event, rule_parameters=rule_parameters
    )

    # Assert the expected compliance decision
    assert compliance_decision == "COMPLIANT"
