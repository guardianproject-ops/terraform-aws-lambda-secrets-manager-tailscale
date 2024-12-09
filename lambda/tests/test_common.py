import os
from unittest.mock import MagicMock, patch

import boto3
import pytest
from botocore.exceptions import ClientError
from ts_rotate.common import (
    MANAGERS,
    SecretManager,
    Step,
    dispatch_event,
    get_ssm_secret,
    manager_for,
    secret_manager,
    validate_env_vars,
)


# Test SecretManager base class
def test_secret_manager_init():
    context = {"Type": "test", "Attributes": {"key": "value"}}
    manager = SecretManager(context)
    assert manager.name == "test"
    assert manager.attributes == {"key": "value"}


def test_secret_manager_unimplemented_methods():
    context = {"Type": "test", "Attributes": {}}
    manager = SecretManager(context)

    with pytest.raises(ValueError):
        manager.create_secret()

    # These should log but not raise
    manager.test_secret()
    manager.set_secret()
    manager.finish_secret()


def test_secret_manager_format_payload():
    context = {"Type": "test", "Attributes": {"key": "value"}}
    manager = SecretManager(context)
    payload = manager._format_payload({"new": "attr"})
    assert payload == {"Type": "test", "Attributes": {"new": "attr"}}


# Test decorator and manager registration
def test_secret_manager_decorator():
    @secret_manager("test-type")
    class TestManager(SecretManager):
        pass

    assert "test-type" in MANAGERS
    assert MANAGERS["test-type"] == TestManager


# Test manager_for function
def test_manager_for():
    @secret_manager("test-type")
    class TestManager(SecretManager):
        pass

    context = {"Type": "test-type", "Attributes": {}}
    manager = manager_for(context)
    assert isinstance(manager, TestManager)


def test_manager_for_invalid_type():
    with pytest.raises(ValueError, match="Cannot dispatch on invalid-type"):
        manager_for({"Type": "invalid-type", "Attributes": {}})


# Test dispatch_event function
def test_dispatch_event():
    @secret_manager("test-type")
    class TestManager(SecretManager):
        def create_secret(self):
            return "created"

    context = {"Type": "test-type", "Attributes": {}}
    result = dispatch_event(Step.create_secret, context)
    assert result == "created"


# Test validate_env_vars function
def test_validate_env_vars_success():
    with patch.dict(os.environ, {"TEST_VAR": "value"}):
        result = validate_env_vars(["TEST_VAR"])
        assert result == {"TEST_VAR": "value"}


def test_validate_env_vars_with_default():
    result = validate_env_vars([("TEST_VAR", "default")])
    assert result == {"TEST_VAR": "default"}


def test_validate_env_vars_missing():
    with pytest.raises(ValueError, match="Missing required environment variables"):
        validate_env_vars(["MISSING_VAR"])


# Test get_ssm_secret function
def test_get_ssm_secret_success():
    mock_ssm = MagicMock()
    mock_ssm.get_parameter.return_value = {"Parameter": {"Value": "secret-value"}}

    with patch("boto3.client", return_value=mock_ssm):
        result = get_ssm_secret("/test/param")
        assert result == "secret-value"
        mock_ssm.get_parameter.assert_called_with(
            Name="/test/param", WithDecryption=True
        )


def test_get_ssm_secret_error():
    mock_ssm = MagicMock()
    mock_ssm.get_parameter.side_effect = ClientError(
        {"Error": {"Code": "ParameterNotFound"}}, "GetParameter"
    )

    with patch("boto3.client", return_value=mock_ssm):
        with pytest.raises(ClientError):
            get_ssm_secret("/test/param")


# Cleanup after tests
@pytest.fixture(autouse=True)
def clear_managers():
    MANAGERS.clear()
    yield
