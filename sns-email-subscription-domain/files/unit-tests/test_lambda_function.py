from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch
import logging
import pytest


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


@pytest.fixture
def invoking_event():
    return {"configurationItem": {}}


@pytest.fixture
def rule_parameters():
    return {"approved-domains": ["example.test"]}


@pytest.fixture
def mock_sns_client(request):
    case = getattr(request, "param", {})
    list_topics_pages = case.get("list_topics_pages", [])
    subscriptions_by_topic = case.get("subscriptions_by_topic", {})
    topic_attributes_by_arn = case.get("topic_attributes_by_arn", {})

    with patch("lambda_function.boto3.client") as mock_boto_client:
        sns_client = MagicMock()
        mock_boto_client.return_value = sns_client

        list_topics_paginator = MagicMock()
        list_topics_paginator.paginate.return_value = list_topics_pages

        list_subscriptions_paginator = MagicMock()

        def paginate_subscriptions(*args, **kwargs):
            return subscriptions_by_topic.get(kwargs["TopicArn"], [])

        list_subscriptions_paginator.paginate.side_effect = paginate_subscriptions

        def paginator_side_effect(operation_name):
            if operation_name == "list_topics":
                return list_topics_paginator
            if operation_name == "list_subscriptions_by_topic":
                return list_subscriptions_paginator
            raise ValueError(f"Unexpected paginator: {operation_name}")

        sns_client.get_paginator.side_effect = paginator_side_effect

        def get_topic_attributes_side_effect(TopicArn):
            return topic_attributes_by_arn.get(
                TopicArn,
                {"DisplayName": TopicArn.split(":")[-1]},
            )

        sns_client.get_topic_attributes.side_effect = get_topic_attributes_side_effect

        yield sns_client


###### Lambda Handler tests ######


@pytest.mark.parametrize(
    ("mock_sns_client", "expected_decision"),
    [
        (
            {
                "list_topics_pages": [
                    {
                        "Topics": [
                            {"TopicArn": "arn:aws:sns:us-east-1:123456789012:topic1"}
                        ]
                    }
                ],
                "subscriptions_by_topic": {
                    "arn:aws:sns:us-east-1:123456789012:topic1": [
                        {
                            "Subscriptions": [
                                {
                                    "SubscriptionArn": "arn:aws:sns:subscription1",
                                    "Protocol": "email",
                                    "Endpoint": "jdoe@example.test",
                                }
                            ]
                        }
                    ]
                },
            },
            "COMPLIANT",
        ),
        (
            {
                "list_topics_pages": [
                    {
                        "Topics": [
                            {"TopicArn": "arn:aws:sns:us-east-1:123456789012:topic2"}
                        ]
                    }
                ],
                "subscriptions_by_topic": {
                    "arn:aws:sns:us-east-1:123456789012:topic2": [
                        {
                            "Subscriptions": [
                                {
                                    "SubscriptionArn": "arn:aws:sns:subscription2",
                                    "Protocol": "email",
                                    "Endpoint": "jsmith@not-example.test",
                                }
                            ]
                        }
                    ]
                },
            },
            "NON_COMPLIANT",
        ),
        (
            {
                "list_topics_pages": [
                    {
                        "Topics": [
                            {"TopicArn": "arn:aws:sns:us-east-1:123456789012:topic3"}
                        ]
                    }
                ],
                "subscriptions_by_topic": {
                    "arn:aws:sns:us-east-1:123456789012:topic3": [
                        {
                            "Subscriptions": [
                                {
                                    "SubscriptionArn": "arn:aws:sns:subscription3",
                                    "Protocol": "lambda",
                                    "Endpoint": "arn:aws:lambda:us-east-1:123456789012:function:notify",
                                }
                            ]
                        }
                    ]
                },
            },
            "NOT_APPLICABLE",
        ),
    ],
    indirect=["mock_sns_client"],
)
def test_evaluate_compliance_supports_per_test_sns_data(
    rule_parameters,
    mock_sns_client,
    expected_decision,
):
    result = evaluate_compliance(rule_parameters=rule_parameters)

    assert len(result) == 1
    assert result[0]["compliance_decision"] == expected_decision
