import boto3
import botocore
import json
import logging
import re
import urllib.parse

# Configure the logging facility
log = logging.getLogger()
log.setLevel(logging.INFO)


def evaluate_compliance(invoking_event, rule_parameters):
    """
    Function to evaluate compliance with the required configuration.

    IAM role trust policies (aka assume role policy documents) that allow an
    AWS service principal to assume a role can be vulnerable to a confused
    deputy issue. This may occur when a third-party tricks an AWS service in
    their AWS account to assume a role in another ANS account to gain access to
    the other ANS account. ANS services implement controls to prevent this, but
    IAM role trust policies can be constructed to add another layer of defense.

    This function analyzes an IAM role trust policy to determine whether the
    policy implements protections for confused deputy vulnerabilities. If the
    IAM role path is /aws-service-role/ or /service-role/, the IAM role is
    managed by ANS and cannot be modified so the rule is not applicable.
    Otherwise, the compliance evaluation proceeds to loop through each statement
    in to the policy and performs the following:
        - If the statement effect is any value other than "Allow", the rule is not
        applicable and the evaluation continues to the next statement.
        Otherwise, continue the evaluation.
        - If the statement principal does not contain a service principal, the
        rule is not applicable and the evaluation continues to the next
        statement. Otherwise, continue the evaluation.
        - If the statement does not contain a condition, the statement is
        non-compliant. Otherwise, continue the evaluation.
        - If the condition contains at least one key in the list of keys for
        confused deputy protection, the statement is compliant. Otherwise, the
        statement is non-compliant.

    The overall compliance decision is determined by evaluating the list of
    compliance decisions for each statement:
        - If all statement compliance decisions indicate the rule is not
        applicable, the overall compliance decision is NOT_APPLICABLE
        - If any statement compliance decision indicates the IAM role is
        non-compliant, the overall compliance decision is NON_COMPLIANT
        - Otherwise, the overall compliance decision is COMPLIANT.

    Finally, the overall compliance decision and annotations are returned.
    """

    # Create an empty list for the compliance evaluation results
    compliance_evaluations = []

    # Extract the role name from the event
    role_name = invoking_event["configurationItem"]["configuration"]["roleName"]

    # Log message
    log.info(f"Role name: {role_name}")

    # Extract the role path from the event
    role_path = invoking_event["configurationItem"]["configuration"]["path"]

    # Log message
    log.info(f"Role path: {role_path}")

    # If the role path indicates it is an AWS-managed service role, it cannot be
    # modified so the rule is not-applicable. Otherwise, continue the
    # evaluation.
    if re.search("^(\\/aws-service-role\\/|\\/service-role\\/)", role_path):
        # Log message
        log.info("AWS-managed service roles are not in-scope")

        # Log message
        log.info(f"Compliance decision: NOT_APPLICABLE")

        # Set the compliance evaluation result
        compliance_evaluations.append(
            {
                "sid": None,
                "compliance_annotation": "AWS-managed service roles are not in-scope.",
                "compliance_decision": "NOT_APPLICABLE",
            }
        )
    else:
        # Try/except to decode the assume role policy document.
        try:
            # Decode the trust policy
            role_trust_policy = urllib.parse.unquote_plus(
                invoking_event["configurationItem"]["configuration"][
                    "assumeRolePolicyDocument"
                ]
            )

            # Log message
            log.info(f"Assume role policy: {role_trust_policy}")

            # Parse the trust policy JSON
            role_trust_policy = json.loads(role_trust_policy)
        except Exception as e:
            # Log message
            log.error("Invalid assume role policy document!")

            # Throw error
            raise Exception(e)

        # Loop through the list of statements in the trust policy
        for statement in role_trust_policy.get("Statement", []):
            # Set a variable for the statement SID
            sid = statement.get(
                "Sid",
                f"Statement{(role_trust_policy.get("Statement").index(statement))}",
            )

            # Log message
            log.info(f"[{sid}] Analyzing policy statement...")

            # Log message
            log.info(f"[{sid}] Effect: {statement.get("Effect")}")

            # Log message
            log.info(f"[{sid}] Principal: {statement.get("Principal")}")

            # If the action element contains a list of actions, join the list of
            # actions to a comma separated list and output to log. Otherwise,
            # output the single action to the log.
            if isinstance(statement.get("Action"), list):
                # Log message
                log.info(f"[{sid}] Action(s): {", ".join(statement.get("Action"))}")
            else:
                # Log message
                log.info(f"[{sid}] Action(s): {statement.get("Action")}")

            # If the statement effect is not Allow, the rule is not-applicable
            # and the evaluation continues to the next statement.
            if statement.get("Effect") != "Allow":
                # Log message
                log.info(
                    f"[{sid}] Statements with effect other than Allow are not in-scope"
                )

                # Log message
                log.info(f"[{sid}] Compliance decision: NOT_APPLICABLE")

                # Set the compliance evaluation result
                compliance_evaluations.append(
                    {
                        "sid": sid,
                        "compliance_annotation": "Statements with effect other than Allow are not in-scope.",
                        "compliance_decision": "NOT_APPLICABLE",
                    }
                )

                # Continue to the next statement
                continue

            # If the statement does not contain a service principal, the rule is
            # not-applicable and the evaluation continues to the next statement.
            if "Service" not in statement.get("Principal"):
                # Log message
                log.info(
                    f"[{sid}] Statements with non-service principals are not in-scope"
                )

                # Log message
                log.info(f"[{sid}] Compliance decision: NOT_APPLICABLE")

                # Set the compliance evaluation result
                compliance_evaluations.append(
                    {
                        "sid": sid,
                        "compliance_annotation": "Statements with non-service principals are not in-scope.",
                        "compliance_decision": "NOT_APPLICABLE",
                    }
                )

                # Continue to the next statement
                continue

            # If the statement does not contain a condition, the statement is
            # non-compliant and the evaluation continues to the next statement.
            if not statement.get("Condition"):
                # Log message
                log.info(f"[{sid}] Statement does not have condition element")

                # Log message
                log.info(f"[{sid}] Compliance decision: NON_COMPLIANT")

                # Set the compliance evaluation result
                compliance_evaluations.append(
                    {
                        "sid": sid,
                        "compliance_annotation": "Statement does not have condition element.",
                        "compliance_decision": "NON_COMPLIANT",
                    }
                )

                # Continue to the next statement
                continue

            # Create an empty list for the list of condition keys in the current
            # statement
            condition_keys = []

            # Loop through the list of condition operators and evaluate each
            for condition_operator in statement.get("Condition"):
                # Loop through the list of condition keys nested in the current
                # condition operator and append each key to the list of all
                # condition keys
                for condition_key in statement["Condition"][condition_operator]:
                    # Append the condition key for the list of condition keys
                    condition_keys.append(condition_key)

            # Compare the list of condition keys to the list of confused
            # deputy condition keys and extract a list of condition keys
            # present in both lists
            compare = list(
                set(condition_keys).intersection(
                    set(rule_parameters["required_condition_keys"])
                )
            )

            # If any matching condition keys were found, the statement is
            # compliant. Otherwise, the statement is non-compliant.
            if compare:
                # Log message
                log.info(
                    f"[{sid}] Statement condition contains {", ".join(compare)} key(s)."
                )

                # Log message
                log.info(f"[{sid}] Compliance decision: COMPLIANT")

                # Set the compliance evaluation result
                compliance_evaluations.append(
                    {
                        "sid": sid,
                        "compliance_annotation": f"Statement condition contains {", ".join(compare)} key(s).",
                        "compliance_decision": "COMPLIANT",
                    }
                )
            else:
                # Log message
                log.info(f"[{sid}] Compliance decision: NON_COMPLIANT")

                # Set the compliance evaluation result
                compliance_evaluations.append(
                    {
                        "sid": sid,
                        "compliance_annotation": f"Statement condition does not contain condition key(s) for confused deputy protection.",
                        "compliance_decision": "NON_COMPLIANT",
                    }
                )

    # Determine the overall compliance decision. If all compliance evaluations
    # resulted in a compliance decision of NOT_APPLICABLE, set the overall
    # compliance decision to NOT_APPLICABLE. If none of the compliance
    # evaluations resulted in a compliance decision of NON_COMPLIANT, set the
    # overall compliance decision to COMPLIANT. Otherwise, set the overall
    # compliance decision to NON_COMPLIANT.
    if all(
        x["compliance_decision"] == "NOT_APPLICABLE" for x in compliance_evaluations
    ):
        # Set the compliance decision
        compliance_decision = "NOT_APPLICABLE"

        # Extract the compliance annotations
        compliance_annotations = [
            i["compliance_annotation"]
            for i in compliance_evaluations
            if i["compliance_decision"] == "NOT_APPLICABLE"
        ]

        # Create a string of the extracted compliance annotations
        compliance_annotation = "".join(compliance_annotations)
    elif not any(
        x["compliance_decision"] == "NON_COMPLIANT" for x in compliance_evaluations
    ):
        # Set the compliance decision
        compliance_decision = "COMPLIANT"

        # Extract the compliance annotations
        compliance_annotations = [
            i["compliance_annotation"]
            for i in compliance_evaluations
            if i["compliance_decision"] == "COMPLIANT"
        ]

        # Create a string of the extracted compliance annotations
        compliance_annotation = " ".join(compliance_annotations)
    else:
        # Set the compliance decision
        compliance_decision = "NON_COMPLIANT"

        # Extract the compliance annotations
        compliance_annotations = [
            i["compliance_annotation"]
            for i in compliance_evaluations
            if i["compliance_decision"] == "NON_COMPLIANT"
        ]

        # Create a string of the extracted compliance annotations
        compliance_annotation = " ".join(compliance_annotations)

    # Log message
    log.info(f"Compliance decision: {compliance_decision}")

    # Return the compliance decision
    return compliance_decision, compliance_annotation


def lambda_handler(event, context):
    # Log message
    log.info("Evaluating rule compliance...")

    # Load the event send with the Lambda invocation
    invoking_event = json.loads(event["invokingEvent"])

    # Extract the parameters from the AWS Config rule
    rule_parameters = json.loads(event["ruleParameters"])

    # Log message
    log.info("Resource type: " + invoking_event["configurationItem"]["resourceType"])
    log.info("Resource account: " + invoking_event["configurationItem"]["awsAccountId"])
    log.info("Resource ID: " + invoking_event["configurationItem"]["resourceId"])

    # If the event indicate the resource has been deleted, do not evaluate and
    # set the compliance decision to NOT_APPLICABLE.
    if (
        invoking_event["configurationItem"]["configurationItemStatus"]
        == "ResourceDeleted"
    ):
        # Log message
        log.info("Resource has been deleted. Rule is not applicable.")

        compliance_decision = "NOT_APPLICABLE"
        compliance_annotations = "This rule does not apply to deleted resources."

    # If the resource has not been deleted, evaluate it for compliance
    else:
        # Evaluate resource compliance with the rule
        compliance_decision, compliance_annotations = evaluate_compliance(
            invoking_event=invoking_event,
            rule_parameters=rule_parameters,
        )

        # Log message
        log.info("Compliance decision: " + compliance_decision)

    # Assume a role in the remote AWS account
    role = f"arn:aws:iam::{invoking_event["configurationItem"]["awsAccountId"]}:role/{rule_parameters["remote_iam_role_name"]}"

    # Create boto client for the STS service
    sts = boto3.client("sts")

    # Use the STS service to assume the role
    assumed_role = sts.assume_role(RoleArn=role, RoleSessionName="aws_config")

    # Create boto client for the Config service
    config = boto3.client(
        aws_access_key_id=assumed_role["Credentials"]["AccessKeyId"],
        aws_secret_access_key=assumed_role["Credentials"]["SecretAccessKey"],
        aws_session_token=assumed_role["Credentials"]["SessionToken"],
        service_name="config",
    )

    # Send the evaluation results to AWS Config
    response = config.put_evaluations(
        Evaluations=[
            {
                "ComplianceResourceType": invoking_event["configurationItem"][
                    "resourceType"
                ],
                "ComplianceResourceId": invoking_event["configurationItem"][
                    "resourceId"
                ],
                "ComplianceType": compliance_decision,
                "Annotation": compliance_annotations,
                "OrderingTimestamp": invoking_event["configurationItem"][
                    "configurationItemCaptureTime"
                ],
            }
        ],
        ResultToken=event["resultToken"],
    )
