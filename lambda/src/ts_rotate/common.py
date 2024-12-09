# SPDX-License-Identifier: GPL-v3
import logging
from enum import StrEnum
from functools import wraps
from os import environ
from typing import Callable, Dict, List, Optional, Tuple, Type, TypeVar, Union

import boto3

T = TypeVar("T", bound="SecretManager")


logger = logging.getLogger()


class Step(StrEnum):
    create_secret = "create_secret"
    test_secret = "test_secret"
    set_secret = "set_secret"
    finish_secret = "finish_secret"


class SecretManager:
    def __init__(self, context: Dict):
        self.name = context["Type"]
        self.attributes = context["Attributes"]

    def create_secret(self):
        raise ValueError(f"createSecret({self.name}): Not implemented")

    def test_secret(self):
        logger.info(f"testSecret({self.name}): Not implemented")

    def set_secret(self):
        logger.info(f"setSecret({self.name}): Not implemented")

    def finish_secret(self):
        logger.info(f"finishSecret({self.name}): Not implemented")

    def _format_payload(self, attributes: Dict) -> Dict:
        return {"Type": self.name, "Attributes": attributes}


MANAGERS: Dict[str, Type[SecretManager]] = {}


def secret_manager(secret_type: str):
    """Decorator to register a SecretManager implementation for a specific secret type."""

    def decorator(cls: Type[T]) -> Type[T]:
        MANAGERS[secret_type] = cls
        return cls

    return decorator


def manager_for(context: Dict) -> SecretManager:
    secret_type = context["Type"]
    manager_cls = MANAGERS.get(secret_type)
    if manager_cls:
        return manager_cls(context)
    raise ValueError(f"Cannot dispatch on {secret_type}")


def dispatch_event(step: Step, context: Dict):
    mgr = manager_for(context)
    if not mgr:
        raise ValueError("Cannot dispatch on context type")

    method = getattr(mgr, step.value, None)
    if not method:
        raise ValueError(f"mgr {mgr.name} does not support step {step.value}")

    return method()


def validate_env_vars(
    required: List[Union[str, Tuple[str, str]]]
) -> Union[Dict[str, str], ValueError]:
    """
    Validates required environment variables exist and returns their values.

    Args:
        required: List of either string keys or tuples of (key, default_value)

    Returns:
        Dict of environment variable values on success
        ValueError with missing keys list on failure


    Usage example:
        required = [
            "AWS_REGION",
            ("LOG_LEVEL", "INFO"),
            "DB_PASSWORD"
        ]

        try:
            env = validate_env_vars(required)
            # Use env["AWS_REGION"], env["LOG_LEVEL"] etc
        except ValueError as e:
            # handle error..
    """
    result = {}
    missing = []

    for item in required:
        if isinstance(item, tuple):
            key, default = item
            result[key] = environ.get(key, default)
        else:
            key = item
            value = environ.get(key)
            if value is None:
                missing.append(key)
            else:
                result[key] = value

    if missing:
        raise ValueError(
            f"Missing required environment variables: {', '.join(missing)}"
        )

    return result


def get_ssm_secret(param_name: str) -> Optional[str]:
    """
    Gets a SecureString parameter value from SSM Parameter Store using its name

    Args:
        param_Name: The name of the SSM parameter

    Returns:
        The decrypted parameter value or None if parameter not found

    Raises:
        boto3.exceptions.ClientError: For AWS API errors
    """

    ssm = boto3.client("ssm")
    response = ssm.get_parameter(Name=param_name, WithDecryption=True)
    return response["Parameter"]["Value"]
