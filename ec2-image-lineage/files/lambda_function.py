from botocore.exceptions import ClientError
from tabulate import tabulate
import boto3
import botocore
import json
import logging
import os
import re
import urllib.parse

# Configure the logging facility
log = logging.getLogger()
log.setLevel(logging.INFO)

# Create a Config client
config = boto3.client(service_name="config")

# Create a EC2 client
ec2 = boto3.client(service_name="ec2")

# Create a STS client
sts = boto3.client(service_name="sts")


def evaluate_compliance(invoking_event: dict, rule_parameters: dict) -> tuple:
    # Set a variable for the value of the APPROVED_IMAGE_IDS rule parameter
    approved_image_ids = rule_parameters.get("APPROVED_IMAGE_IDS", None)

    # Parse the approved image IDs to a list
    approved_image_ids = (
        list(approved_image_ids.split(",")) if approved_image_ids != None else list([])
    )

    # Log message
    log.info(f"Approved image IDs: {", ".join(approved_image_ids)}")

    # Set a variable for the value of the APPROVED_IMAGE_OWNER_ALIASES rule parameter
    approved_image_owner_aliases = rule_parameters.get(
        "APPROVED_IMAGE_OWNER_ALIASES", None
    )

    # Parse the approved image owner aliases to a list
    approved_image_owner_aliases = (
        list(approved_image_owner_aliases.split(","))
        if approved_image_owner_aliases != None
        else list([])
    )

    # Log message
    log.info(f"Approved image owner aliases: {", ".join(approved_image_owner_aliases)}")

    # Set a variable for the value of the APPROVED_IMAGE_OWNER_IDS rule parameter
    approved_image_owner_ids = rule_parameters.get("APPROVED_IMAGE_OWNER_IDS", None)

    # Parse the approved image owner IDs to a list
    approved_image_owner_ids = (
        list(approved_image_owner_ids.split(","))
        if approved_image_owner_ids != None
        else list([])
    )

    # Get the current AWS account ID
    caller_identity = sts.get_caller_identity()

    # Append the current AWS account ID to the list of approved image owner IDs
    approved_image_owner_ids.append(caller_identity["Account"])

    # Log message
    log.info(f"Approved image owner IDs: {", ".join(approved_image_owner_ids)}")

    # Extract the configuration item
    configuration_item = invoking_event["configurationItem"]

    # Set the initial compliance decision to non-compliant so the rule assumes
    # the resource is not in compliance until proven otherwise.
    compliance_decision = "NON_COMPLIANT"

    # Create an empty list for annotations to send to AWS Config
    compliance_annotations = []

    # Log message
    log.info(
        f"Analyzing EC2 instance {configuration_item['resourceId']} image lineage..."
    )

    # Create an empty list for the image lineage results
    ec2_image_lineage = []

    # Get the EC2 image detail
    ec2_image = get_ec2_image(configuration_item["configuration"].get("imageId"))

    # Determine the EC2 image approval status
    ec2_image = get_ec2_image_approval(
        approved_image_ids=approved_image_ids,
        approved_image_owner_aliases=approved_image_owner_aliases,
        approved_image_owner_ids=approved_image_owner_ids,
        ec2_image=ec2_image,
    )

    # Append the EC2 image detail to the image lineage list
    ec2_image_lineage.append(ec2_image)

    # If the EC2 image detail contains a source image ID parameter, continue retrieving
    # lineage details for each source image
    while ec2_image.get("SourceImageId", None) != None:
        # Get the EC2 image detail
        ec2_image = get_ec2_image(ec2_image_id=ec2_image["SourceImageId"])

        # Determine the EC2 image approval status
        ec2_image = get_ec2_image_approval(
            approved_image_ids=approved_image_ids,
            approved_image_owner_aliases=approved_image_owner_aliases,
            approved_image_owner_ids=approved_image_owner_ids,
            ec2_image=ec2_image,
        )

        # Append the EC2 image detail to the image lineage list
        ec2_image_lineage.append(ec2_image)

    # Create a table of the EC2 image lineage to output
    ec2_image_lineage_table = tabulate(
        headers="keys",
        numalign="left",
        tablefmt="simple_grid",
        tabular_data=ec2_image_lineage,
    )

    # Log message
    log.info("EC2 Image Lineage:")

    # Log message
    log.info(f"\n{ec2_image_lineage_table}")

    # Determine if all EC2 images in the EC2 image lineage are approved
    ec2_image_lineage_approved = all(
        ec2_image.get("Approved", False) for ec2_image in ec2_image_lineage
    )

    # Output the EC2 image lineage approval status
    if ec2_image_lineage_approved:
        # Log message
        log.info("All images in EC2 image lineage are approved")

        # Append message to compliance annotations
        compliance_annotations.append("All images in EC2 image lineage are approved.")

        # Set the compliance decision
        compliance_decision = "COMPLIANT"
    else:
        # Extract a list of the unapproved EC2 images
        ec2_image_lineage_unapproved_images = [
            i for i in ec2_image_lineage if i.get("Approved", False)
        ]

        # Join the list of unapproved EC2 images
        ec2_image_lineage_unapproved_images = ", ".join(
            ec2_image_lineage_unapproved_images
        )

        # Log message
        log.info(
            f"EC2 image lineage contains unapproved image(s): {ec2_image_lineage_unapproved_images}."
        )

        # Append message to compliance annotations
        compliance_annotations.append(
            f"EC2 image lineage contains unapproved image(s): {ec2_image_lineage_unapproved_images}."
        )

        # Set the compliance decision
        compliance_decision = "NON_COMPLIANT"

    # Return the compliance decision
    return compliance_decision, (" ".join(compliance_annotations))


def get_ec2_image(ec2_image_id: str) -> dict:
    # Log message
    log.info(f"[{ec2_image_id}] Getting image detail...")

    # Try/except to get the EC2 image details
    try:
        # Get the EC2 image details
        ec2_images = ec2.describe_images(ImageIds=[ec2_image_id])

        # Set a variable to the EC2 image details
        ec2_image = ec2_images["Images"][0]

        # Log message
        log.info(f"[{ec2_image_id}] Name: {ec2_image['Name']}")

        # Log message
        log.info(
            f"[{ec2_image_id}] Source image ID: {ec2_image.get('SourceImageId', None)}"
        )

        # Append the image details to the image lineage list. Assume the approval status is false.
        return {
            "ImageId": ec2_image.get("ImageId"),
            "State": ec2_image.get("State"),
            "Name": ec2_image.get("Name"),
            "OwnerId": ec2_image.get("OwnerId"),
            "OwnerAlias": ec2_image.get("ImageOwnerAlias", "None"),
            "CreationDate": ec2_image.get("CreationDate"),
            "DeprecationTime": ec2_image.get("DeprecationTime", "None"),
            "SourceImageId": ec2_image.get("SourceImageId", "None"),
            "Approved": False,
        }
    except ClientError as e:
        # If the error is that the image ID was not found, return the
        # unavailable image details.
        if e.response["Error"]["Code"] == "InvalidAMIID.NotFound":
            # Log message
            log.info(f"[{ec2_image_id}] Image was not found!")

            # Append the image details to the image lineage list. Assume the approval status is false.
            return {
                "ImageId": ec2_image_id,
                "State": "unavailable",
                "Name": None,
                "OwnerId": None,
                "OwnerAlias": None,
                "CreationDate": None,
                "DeprecationTime": None,
                "SourceImageId": None,
                "Approved": False,
            }
        else:
            # Log message
            log.error(f"[{ec2_image_id}] Error: {e}")

            # Raise error
            raise


def get_ec2_image_approval(
    approved_image_ids: list,
    approved_image_owner_aliases: list,
    approved_image_owner_ids: list,
    ec2_image: dict,
) -> dict:
    # Log message
    log.info(f"[{ec2_image.get('ImageId')}] Checking image approval...")

    # If the ImageId is in the list of approved image IDs, it is approved
    if ec2_image.get("ImageId") in approved_image_ids:
        # Log message
        log.info(f"[{ec2_image.get('ImageId')}] Approved by ImageId")

        # Set the approval status
        ec2_image["Approved"] = True

    # If the OwnerAlias is in the list of approved image owner aliases, it is approved
    elif ec2_image.get("OwnerAlias") in approved_image_owner_aliases:
        # Log message
        log.info(f"[{ec2_image.get('ImageId')}] Approved by OwnerAlias")

        # Set the approval status
        ec2_image["Approved"] = True

    # If the OwnerId is in the list of approved image owner IDs, it is approved
    elif ec2_image.get("OwnerId") in approved_image_owner_ids:
        # Log message
        log.info(f"[{ec2_image.get('ImageId')}] Approved by OwnerId")

        # Set the approval status
        ec2_image["Approved"] = True

    else:
        # Log message
        log.info(f"[{ec2_image.get('ImageId')}] Image is not approved")

        # Set the approval status
        ec2_image["Approved"] = False

    # Return the EC2 image detail
    return ec2_image


# Define the main Lambda handler function
def lambda_handler(event, context):
    # Log message
    log.info(event)

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

    # Create boto client for the Config service
    config = boto3.client(service_name="config")

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
