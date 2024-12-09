import os
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest
import requests
from requests.exceptions import HTTPError
from ts_rotate import common
from ts_rotate.tailscale import (
    AccessToken,
    AuthKeyManager,
    AuthKeyRequest,
    AuthToken,
    create_auth_key,
    create_auth_key_payload,
    get_access_token,
    get_auth_key,
    list_auth_keys,
)

MOCK_KEY_REQUEST = {
    "tags": ["tag:abel-poc-test"],
    "description": "a test",
    "expiry_seconds": 10,
    "reusable": True,
    "ephemeral": False,
}

MOCK_API_RESPONSE = {
    "access_token": "test_token",
    "expires_in": 3600,
    "scope": "all",
}

MOCK_AUTH_KEY = {
    "id": "test_id",
    "created": "2024-01-01T00:00:00Z",
    "expires": "2024-01-02T00:00:00Z",
    "revoked": "",
    "description": "test key",
    "invalid": False,
    "capabilities": {},
}


@pytest.fixture(autouse=True)
def mock_boto3_credentials():
    with patch("boto3.client") as mock_client:
        # Mock the SSM client
        mock_ssm = MagicMock()
        mock_client.return_value = mock_ssm
        # Configure the mock SSM client's get_parameter method
        mock_ssm.get_parameter.return_value = {"Parameter": {"Value": "test-value"}}
        yield mock_client


@pytest.fixture(autouse=True)
def mock_environment():
    with patch.dict(
        os.environ,
        {
            "TS_CLIENT_ID_PARAM": "/path/to/client/id",
            "TS_CLIENT_SECRET_PARAM": "/path/to/client/secret",
        },
    ):
        yield


# AccessToken tests
def test_access_token_creation():
    token = AccessToken(MOCK_API_RESPONSE, "test-tailnet")
    assert token._token == "test_token"
    assert token.tailnet == "test-tailnet"
    assert token.scope == "all"
    assert not token.is_expiring_soon(buffer_seconds=0)


def test_access_token_expiring():
    api_resp = MOCK_API_RESPONSE.copy()
    api_resp["expires_in"] = 60  # 1 minute
    token = AccessToken(api_resp, "test-tailnet")
    assert token.is_expiring_soon(buffer_seconds=120)


def test_access_token_property():
    token = AccessToken(MOCK_API_RESPONSE, "test-tailnet")
    with patch.object(token, "is_expiring_soon", return_value=True):
        with pytest.raises(Exception, match="Access Token is expiring soon"):
            _ = token.token


# API function tests
@patch("requests.post")
def test_get_access_token(mock_post):
    mock_response = MagicMock()
    mock_response.json.return_value = MOCK_API_RESPONSE
    mock_post.return_value = mock_response

    token = get_access_token("client_id", "client_secret", "test-tailnet")
    assert isinstance(token, AccessToken)
    assert token.tailnet == "test-tailnet"


@patch("requests.post")
def test_get_access_token_error(mock_post):
    mock_post.side_effect = HTTPError("API Error")
    with pytest.raises(HTTPError):
        get_access_token("client_id", "client_secret", "test-tailnet")


def test_auth_key_request():
    request = AuthKeyRequest(
        tags=["tag1", "tag2"],
        description="test key",
        expiry_seconds=3600,
    )
    payload = create_auth_key_payload("test-tailnet", request)
    assert "url" in payload
    assert "json" in payload
    assert payload["json"]["capabilities"]["devices"]["create"]["tags"] == [
        "tag1",
        "tag2",
    ]


@patch("requests.get")
def test_get_auth_key(mock_get):
    mock_response = MagicMock()
    mock_response.json.return_value = MOCK_AUTH_KEY
    mock_get.return_value = mock_response

    token = AccessToken(MOCK_API_RESPONSE, "test-tailnet")
    auth_key = get_auth_key(token, "key_id")
    assert isinstance(auth_key, AuthToken)
    assert auth_key.id == "test_id"


@patch("requests.get")
def test_list_auth_keys(mock_get):
    mock_response = MagicMock()
    mock_response.json.return_value = {"keys": [MOCK_AUTH_KEY]}
    mock_get.return_value = mock_response

    token = AccessToken(MOCK_API_RESPONSE, "test-tailnet")
    keys = list_auth_keys(token)
    assert len(keys) == 1
    assert isinstance(keys[0], AuthToken)


# AuthKeyManager tests
@patch("ts_rotate.common.get_ssm_secret")
def test_auth_key_manager_init(mock_get_ssm):
    mock_get_ssm.side_effect = ["test_client_id", "test_client_secret"]

    with patch("ts_rotate.tailscale.get_access_token") as mock_get_token:
        mock_get_token.return_value = AccessToken(MOCK_API_RESPONSE, "test-tailnet")

        context = {"Type": "auth-key", "Attributes": {"key_request": MOCK_KEY_REQUEST}}
        manager = AuthKeyManager(context)
        assert manager.name == "auth-key"


def test_auth_key_manager_test_secret(mock_environment, mock_boto3_credentials):
    mock_get_auth_key = MagicMock(return_value=AuthToken(**MOCK_AUTH_KEY))

    context = {
        "Type": "auth-key",
        "Attributes": {"id": "test_id", "key_request": MOCK_KEY_REQUEST},
    }

    with (
        patch("ts_rotate.tailscale.get_auth_key", mock_get_auth_key),
        patch("ts_rotate.tailscale.get_access_token") as mock_get_token,
    ):
        mock_get_token.return_value = AccessToken(MOCK_API_RESPONSE, "test-tailnet")
        manager = AuthKeyManager(context)
        manager.test_secret()


def test_auth_key_manager_test_secret_invalid(mock_environment, mock_boto3_credentials):
    invalid_key = MOCK_AUTH_KEY.copy()
    invalid_key["invalid"] = True

    context = {
        "Type": "auth-key",
        "Attributes": {"id": "test_id", "key_request": MOCK_KEY_REQUEST},
    }

    with (
        patch("ts_rotate.tailscale.get_auth_key") as mock_get_auth_key,
        patch("ts_rotate.tailscale.get_access_token") as mock_get_token,
    ):
        mock_get_auth_key.return_value = AuthToken(**invalid_key)
        mock_get_token.return_value = AccessToken(MOCK_API_RESPONSE, "test-tailnet")
        manager = AuthKeyManager(context)
        with pytest.raises(ValueError, match="is invalid"):
            manager.test_secret()


# Cleanup
@pytest.fixture(autouse=True)
def clear_managers():
    if hasattr(common, "MANAGERS"):
        common.MANAGERS.clear()
    yield
