import json
import os
from datetime import datetime
from unittest.mock import MagicMock, patch

import botocore
import pytest
import requests
from ts_rotate import common, handler, tailscale

create_event = {
    "ClientRequestToken": "819116bc-4ba3-4cb1-8e14-3c8a69de6aa8",
    "RotationToken": "ebcba96c-c192-488d-b3a1-b67ee010c7f5",
    "SecretId": "arn:aws:secretsmanager:eu-central-1:12345678:secret:gpex-dev-ts-rotate/tailscale3-yFRUKP",
    "Step": "createSecret",
}
set_event = {
    "ClientRequestToken": "819116bc-4ba3-4cb1-8e14-3c8a69de6aa8",
    "RotationToken": "9830493b-6750-4773-ba8b-6380ef8127c1",
    "SecretId": "arn:aws:secretsmanager:eu-central-1:12345678:secret:gpex-dev-ts-rotate/tailscale3-yFRUKP",
    "Step": "setSecret",
}
test_event = {
    "ClientRequestToken": "819116bc-4ba3-4cb1-8e14-3c8a69de6aa8",
    "RotationToken": "7021476a-f327-4207-90de-ddc414772be8",
    "SecretId": "arn:aws:secretsmanager:eu-central-1:12345678:secret:gpex-dev-ts-rotate/tailscale3-yFRUKP",
    "Step": "testSecret",
}
finish_event = {
    "ClientRequestToken": "819116bc-4ba3-4cb1-8e14-3c8a69de6aa8",
    "RotationToken": "d363e29d-5d50-47db-b4fb-6483a607e193",
    "SecretId": "arn:aws:secretsmanager:eu-central-1:12345678:secret:gpex-dev-ts-rotate/tailscale3-yFRUKP",
    "Step": "finishSecret",
}

context = {}


@pytest.fixture
def mock_boto3_client():
    with patch("boto3.client") as mock_client:
        # Set up the exceptions factory for secretsmanager
        model = botocore.session.get_session().get_service_model("secretsmanager")
        factory = botocore.errorfactory.ClientExceptionsFactory()
        exceptions = factory.create_client_exceptions(model)

        mock_instance = MagicMock()
        mock_instance.exceptions = exceptions
        mock_client.return_value = mock_instance

        yield mock_instance


@pytest.fixture
def mock_secret_dict():
    return {
        "Type": "auth-key",
        "Attributes": {
            "id": "test-id",
            "token_value": "test-token",
            "description": "test description",
            "key_request": {
                "tags": ["test-tag"],
                "expiry_seconds": 3600,
                "reusable": True,
                "ephemeral": False,
                "description": "test key request",
            },
        },
    }


@patch("ts_rotate.common.dispatch_event")
def test_create_secret_step(mock_dispatch_event, mock_boto3_client, mock_secret_dict):
    mock_boto3_client.describe_secret.return_value = {
        "RotationEnabled": True,
        "VersionIdsToStages": {create_event["ClientRequestToken"]: ["AWSPENDING"]},
    }

    err = {
        "Code": "ResourceNotFoundException",
        "Message": "Secrets Manager can't find the specified secret.",
    }

    # Mock get_secret_value to return different responses/exceptions in sequence
    mock_boto3_client.get_secret_value.side_effect = [
        # First call (AWSCURRENT) - should raise ResourceNotFoundException
        mock_boto3_client.exceptions.ResourceNotFoundException(
            error_response={
                "Error": err,
            },
            operation_name="GetSecretValue",
        ),
        # Second call (TFINIT) - should return the mock secret
        {
            "ARN": "arn:aws:secretsmanager:eu-central-1:12345678:secret:gpex-dev-ts-rotate/tailscale3-yFRUKP",
            "VersionId": "819116bc-4ba3-4cb1-8e14-3c8a69de6aa8",
            "Name": "test",
            "CreatedDate": "2024-12-09T13:18:41.751000+01:00",
            "SecretString": json.dumps(mock_secret_dict),
        },
        # Third call (AWSPENDING) - should raise ResourceNotFoundException
        mock_boto3_client.exceptions.ResourceNotFoundException(
            error_response={"Error": err},
            operation_name="GetSecretValue",
        ),
    ]

    ret = {"FOO": "BAR"}
    mock_dispatch_event.return_value = ret

    handler.lambda_handler(create_event, context)

    # Verify the calls
    mock_boto3_client.describe_secret.assert_called_once()
    assert mock_boto3_client.get_secret_value.call_count == 3
    mock_dispatch_event.assert_called_once_with(
        common.Step.create_secret, mock_secret_dict
    )
    mock_boto3_client.put_secret_value.assert_called_once_with(
        SecretId=create_event["SecretId"],
        ClientRequestToken=create_event["ClientRequestToken"],
        SecretString=json.dumps(ret),
        VersionStages=["AWSPENDING"],
    )
