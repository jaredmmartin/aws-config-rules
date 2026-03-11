from datetime import datetime, timedelta, timezone
import boto3
import botocore
import json
import logging
import os
import re

# Configure the logging facility
log = logging.getLogger()
log.setLevel(logging.INFO)


def evaluate_compliance(rule_parameters):
    """
    Function to evaluate a resources compliance with the required configuration.

    This function analyzes SNS topic subscriptions to determine whether each
    subscription of the "email" or "email-json" protocol uses an email target
    with an approved domain.

    This function retrieves a list of all SNS topics and all subscriptions for
    each topic. The compliance evaluation loops through each SNS topic and
    subscription and performs the following:
        - If the subscription protocol is any type other than
        "email" or "email-json", the SNS topic subscription is NOT_APPLICABLE.
        - If the subscription protocol is either "email" or "email-json", the
        function extracts the domain of the subscription target endpoint and
        checks if the domain is in the list of approved domains. The list of
        approved domains is specified in the Config rule parameter named
        "approved-domains".
        - If the domain is in the list of approved domains, the compliance
        decision is COMPLIANT. Otherwise, the compliance decision is
        NON_COMPLIANT.

    AWS Config doesn't have a standalone resource type for SNS topic
    subscriptions so this rule is applied to SNS topics. All subscriptions
    associated with the SNS topic are evaluated for compliance and the
    compliance decision for the SNS topic is determined based on the list of
    compliance decisions for its subscriptions:
        - If all compliance decisions for an SNS topic are NOT_APPLICABLE, the
        overall compliance decision is NOT_APPLICABLE
        - If no compliance decision for any subscription associated with the SNS
        topic is NON_COMPLIANT, the overall compliance decision is
        COMPLIANT
        - Otherwise, the SNS topic is COMPLIANT.

    Parameters:
        rule_parameters (dict): A dictionary containing parameters of the Config
            rule

    Returns:
        list[dict]: A dictionary containing the results of the compliance evaluation
        containing the following properties:
            arn: SNS topic ARN
            name: SNS topic display name
            compliance_decision: Compliance state
            compliance_annotations: Details of the compliance evaluation
            subscriptions: List of SNS topic subscriptions
    """

    # Create a SNS client
    sns = boto3.client(service_name="sns")

    # Create an empty list for the compliance evaluation results
    compliance_evaluations = []

    # Set a variable for the operating system exclusions parameter
    approved_domains = rule_parameters.get("approved-domains", [])

    # Log message
    log.info(f"Approved domains: {approved_domains}")

    # Log message
    log.info("Getting SNS topic subscriptions...")

    # Create empty list for SNS topics
    sns_topics = []

    # Create paginator to get all SNS topics
    paginator = sns.get_paginator("list_topics")

    # Use paginator to get all topics
    page_iterator = paginator.paginate(PaginationConfig={})

    # Loop through each page
    for page in page_iterator:
        # Loop through the SNS topics in each page
        for page_sns_topic in page["Topics"]:
            # Append the topic to the list of topics
            sns_topics.append(page_sns_topic)

    # Loop through the list of SNS topics and evaluate each
    for sns_topic in sns_topics:
        # Get the SNS topic details
        sns_topic_attributes = sns.get_topic_attributes(TopicArn=sns_topic["TopicArn"])

        # Set a variable for the SNS topic display name
        sns_topic_name = sns_topic_attributes["DisplayName"]

        # Create the compliance evaluation dictionary for the current topics
        compliance_evaluation = {
            "arn": sns_topic["TopicArn"],
            "name": sns_topic_name,
            "compliance_annotations": [],
            "compliance_decision": "NON_COMPLIANT",
            "subscriptions": [],
        }

        # Log message
        log.info(f"[{sns_topic_name}] Getting topic subscriptions...")

        # Create empty list for subscriptions
        sns_topic_subscriptions = []

        # Create paginator to get all SNS topic subscriptions
        paginator = sns.get_paginator("list_subscriptions_by_topic")

        # Use paginator to get all topics
        page_iterator = paginator.paginate(TopicArn=sns_topic["TopicArn"])

        ## Loop through each page
        for page in page_iterator:
            # Loop through the SNS topics in each page
            for page_sns_subscription in page["Subscriptions"]:
                # Append the topic to the list of topics
                sns_topic_subscriptions.append(page_sns_subscription)

        # Loop through the list of subscriptions and evaluate each
        for subscription in sns_topic_subscriptions:
            # If the subscription is not an email subscription, the rule is not
            # applicable. Otherwise, continue the compliant evaluation.
            if subscription["Protocol"] not in ["email", "email-json"]:
                # Log message
                log.info(
                    f"[{sns_topic_name}] [{subscription['SubscriptionArn']}] Subscription type ({subscription['Protocol']}) is not in-scope"
                )

                # Log message
                log.info(
                    f"[{sns_topic_name}] [{subscription['SubscriptionArn']}] Rule is not applicable"
                )

                # Append the compliance evaluation results for the current
                # subscription to the list of subscriptions for the current
                # topic
                compliance_evaluation["subscriptions"].append(
                    {
                        "compliance_decision": "NOT_APPLICABLE",
                        "compliance_annotation": f"Subscription type ({subscription['Protocol']}) is not in-scope.",
                        "subscription_arn": subscription["SubscriptionArn"],
                        "subscription_protocol": subscription["Protocol"],
                    }
                )

                # Continue to the next subscription
                continue

            # Log message
            log.info(
                f"[{sns_topic_name}] [{subscription['SubscriptionArn']}] Evaluating compliance..."
            )

            # Split the email address of the subscription and extract the domain
            subscription_domain = (subscription["Endpoint"].split("@"))[1]

            # If the subscription domain is in the list of approved domains, the
            # current subscription is COMPLIANT. Otherwise, the current
            # subscription is NON_COMPLIANT.
            if subscription_domain in approved_domains:
                # Log message
                log.info(
                    f"[{sns_topic_name}] [{subscription['SubscriptionArn']}] {subscription_domain} is in the list of approved domains"
                )

                # Log message
                log.info(
                    f"[{sns_topic_name}] [{subscription['SubscriptionArn']}] Resource is compliant"
                )

                # Append the compliance evaluation results for the current
                # subscription to the list of subscriptions for the current
                # topic
                compliance_evaluation["subscriptions"].append(
                    {
                        "compliance_decision": "COMPLIANT",
                        "compliance_annotation": f"{subscription['Endpoint']} email subscription is in the list of approved domains.",
                        "subscription_arn": subscription["SubscriptionArn"],
                        "subscription_protocol": subscription["Protocol"],
                    }
                )
            else:
                # Log message
                log.info(
                    f"[{sns_topic_name}] [{subscription['SubscriptionArn']}] {subscription_domain} is not in the list of approved domains"
                )

                # Log message
                log.info(
                    f"[{sns_topic_name}] [{subscription['SubscriptionArn']}] Resource is not compliant"
                )

                # Append the compliance evaluation results for the current
                # subscription to the list of subscriptions for the current
                # topic
                compliance_evaluation["subscriptions"].append(
                    {
                        "compliance_decision": "NON_COMPLIANT",
                        "compliance_annotation": f"{subscription['Endpoint']} email subscription is not in the list of approved domains.",
                        "subscription_arn": subscription["SubscriptionArn"],
                        "subscription_protocol": subscription["Protocol"],
                    }
                )

        # Determine the overall compliance decision for the SNS topic. If all
        # compliance evaluations for the SNS topic resulted in a compliance
        # decision of NOT_APPLICABLE, set the overall compliance decision to
        # NOT_APPLICABLE.
        if all(
            x["compliance_decision"] == "NOT_APPLICABLE"
            for x in compliance_evaluation["subscriptions"]
        ):
            # Set the IAM user compliance decision to compliant
            compliance_evaluation["compliance_decision"] = "NOT_APPLICABLE"

            # Extract the compliance annotations for non-compliant resources
            compliance_annotations = [
                i["compliance_annotation"]
                for i in compliance_evaluation["subscriptions"]
                if i["compliance_decision"] == "NOT_APPLICABLE"
            ]

            # Set the compliance annotations for non-compliant resources
            compliance_evaluation["compliance_annotations"] = " ".join(
                compliance_annotations
            )

            # Log message
            log.info(
                f"{sns_topic_name}] Compliance decision: {compliance_evaluation["compliance_decision"]}"
            )

            # Append the IAM user compliance evaluation to the list of
            # evaluations
            compliance_evaluations.append(compliance_evaluation)
        elif not any(
            x["compliance_decision"] == "NON_COMPLIANT"
            for x in compliance_evaluation["subscriptions"]
        ):
            # Set the IAM user compliance decision to compliant
            compliance_evaluation["compliance_decision"] = "COMPLIANT"

            # Extract the compliance annotations for non-compliant resources
            compliance_annotations = [
                i["compliance_annotation"]
                for i in compliance_evaluation["subscriptions"]
                if i["compliance_decision"] == "COMPLIANT"
            ]

            # Set the compliance annotations for non-compliant resources
            compliance_evaluation["compliance_annotations"] = " ".join(
                compliance_annotations
            )

            # Log message
            log.info(
                f"{sns_topic_name}] Compliance decision: {compliance_evaluation["compliance_decision"]}"
            )

            # Append the IAM user compliance evaluation to the list of
            # evaluations
            compliance_evaluations.append(compliance_evaluation)
        else:
            # Set the IAM user compliance decision to compliant
            compliance_evaluation["compliance_decision"] = "NON_COMPLIANT"

            # Extract the compliance annotations for non-compliant resources
            compliance_annotations = [
                i["compliance_annotation"]
                for i in compliance_evaluation["subscriptions"]
                if i["compliance_decision"] == "NON_COMPLIANT"
            ]

            # Set the compliance annotations for non-compliant resources
            compliance_evaluation["compliance_annotations"] = " ".join(
                compliance_annotations
            )

            # Log message
            log.info(
                f"{sns_topic_name}] Compliance decision: {compliance_evaluation["compliance_decision"]}"
            )

            # Append the IAM user compliance evaluation to the list of
            # evaluations
            compliance_evaluations.append(compliance_evaluation)

    # Return the compliance decision
    return compliance_evaluations


# Define the main Lambda handler function
def lambda_handler(event, context):
    # Log message
    log.info("Evaluating rule compliance...")

    # Create a Config client
    config = boto3.client(service_name="config")

    # Extract the parameters from the AWS Config rule
    rule_parameters = json.loads(event["ruleParameters"])

    # Try/except to perform the compliance evaluation
    try:
        # Evaluate compliance with the rule
        compliance_evaluations = evaluate_compliance(rule_parameters=rule_parameters)

        # Log message
        log.info(f"Sending compliance evaluation results to AWS Config...")

        # Loop through the compliance evaluations and send the results to AWS
        # Config
        for compliance_evaluation in compliance_evaluations:
            # Log message
            log.info(
                f"[{compliance_evaluation["username"]}] {compliance_evaluation["compliance_decision"]}"
            )

            # Send the evaluation results to Config
            response = config.put_evaluations(
                Evaluations=[
                    {
                        "Annotation": " ".join(
                            compliance_evaluation["compliance_annotations"]
                        ),
                        "ComplianceResourceId": compliance_evaluation["arn"],
                        "ComplianceResourceType": "AWS::SNS::Topic",
                        "ComplianceType": compliance_evaluation["compliance_decision"],
                        "OrderingTimestamp": datetime.utcnow(),
                    },
                ],
                ResultToken=event["resultToken"],
            )
    except Exception as e:
        # Log message
        log.error("Lambda function failed.")
        log.error(e)
        log.error(f"Cloudwatch log group: {os.environ['AWS_LAMBDA_LOG_GROUP_NAME']}")
        log.error(f"Cloudwatch log stream: {os.environ['AWS_LAMBDA_LOG_STREAM_NAME']}")
