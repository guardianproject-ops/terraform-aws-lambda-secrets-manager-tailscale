# SPDX-License-Identifier: GPL-v3
import dataclasses
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import requests
from requests.exceptions import HTTPError
from ts_rotate import common


class AccessToken:
    access_token: str
    tailnet: str

    def __init__(self, api_resp, tailnet):
        self._token = api_resp["access_token"]
        self.expires_in = api_resp["expires_in"]
        self.scope = api_resp["scope"]
        self.expiration_time = self._calculate_expiration_time(self.expires_in)
        self.tailnet = tailnet

    def _calculate_expiration_time(self, expires_in):
        return datetime.now() + timedelta(seconds=expires_in)

    def is_expiring_soon(self, buffer_seconds=300):
        return datetime.now() >= self.expiration_time - timedelta(
            seconds=buffer_seconds
        )

    @property
    def token(self):
        if self.is_expiring_soon():
            raise Exception("Access Token is expiring soon")
        return self._token


def get_access_token(
    tailscale_client_id: str, tailscale_client_secret: str, tailnet: str
) -> AccessToken:
    ts_auth_url = "https://api.tailscale.com/api/v2/oauth/token"
    data = {
        "grant_type": "client_credentials",
    }

    r = requests.post(
        ts_auth_url, json=data, auth=(tailscale_client_id, tailscale_client_secret)
    )
    r.raise_for_status()
    return AccessToken(r.json(), tailnet)


from dataclasses import dataclass


@dataclass
class AuthKeyRequest:
    tags: List[str]
    description: str
    expiry_seconds: int
    reusable: bool = False
    ephemeral: bool = True


@dataclass
class AuthToken:
    id: str
    created: str
    expires: str
    description: str
    capabilities: Dict
    invalid: Optional[bool] = False
    revoked: Optional[str] = None
    token_value: Optional[str] = None


def create_auth_key_payload(tailnet: str, key_request: AuthKeyRequest) -> Dict:
    return {
        "url": f"https://api.tailscale.com/api/v2/tailnet/{tailnet}/keys",
        "json": {
            "capabilities": {
                "devices": {
                    "create": {
                        "reusable": key_request.reusable,
                        "ephemeral": key_request.ephemeral,
                        "tags": key_request.tags,
                    }
                }
            },
            "expirySeconds": key_request.expiry_seconds,
            "description": key_request.description,
        },
    }


def get_auth_key(token: AccessToken, key_id: str) -> AuthToken:
    r = requests.get(
        url=f"https://api.tailscale.com/api/v2/tailnet/{token.tailnet}/keys/{key_id}",
        auth=(token.token, ""),
    )
    r.raise_for_status()
    key = r.json()
    return AuthToken(
        id=key["id"],
        created=key["created"],
        expires=key["expires"],
        revoked=key.get("revoked"),
        description=key["description"],
        invalid=key.get("invalid"),
        capabilities=key["capabilities"],
    )


def list_auth_keys(token: AccessToken) -> List[AuthToken]:
    r = requests.get(
        url=f"https://api.tailscale.com/api/v2/tailnet/{token.tailnet}/keys?all=true",
        auth=(token.token, ""),
    )
    r.raise_for_status()
    l = []
    for key in r.json()["keys"]:
        l.append(
            AuthToken(
                id=key["id"],
                created=key["created"],
                expires=key["expires"],
                revoked=key.get("revoked"),
                description=key["description"],
                invalid=key.get("invalid"),
                capabilities=key["capabilities"],
            )
        )
    return l


def delete_auth_key(token: AccessToken, key_id: str) -> None:
    r = requests.delete(
        auth=(token.token, ""),
        url=f"https://api.tailscale.com/api/v2/tailnet/{token.tailnet}/keys/{key_id}",
    )
    r.raise_for_status
    return


def create_auth_key(token: AccessToken, key_request: AuthKeyRequest) -> AuthToken:
    r = requests.post(
        auth=(token.token, ""), **create_auth_key_payload(token.tailnet, key_request)
    )
    r.raise_for_status()

    p = r.json()
    return AuthToken(
        id=p["id"],
        created=p["created"],
        expires=p["expires"],
        description=p["description"],
        invalid=False,
        token_value=p["key"],
        capabilities=p["capabilities"],
        # maybe? created=datetime.fromisoformat(p["created"]),
    )


@common.secret_manager("auth-key")
class AuthKeyManager(common.SecretManager):
    def __init__(self, context: Dict):
        super().__init__(context)
        required = ["TS_CLIENT_ID_PARAM", "TS_CLIENT_SECRET_PARAM", "TS_TAILNET"]
        env = common.validate_env_vars(required)
        self.client_id = common.get_ssm_secret(env["TS_CLIENT_ID_PARAM"])
        self.client_secret = common.get_ssm_secret(env["TS_CLIENT_SECRET_PARAM"])
        self.tailnet = env["TS_TAILNET"]

        self.key_request = AuthKeyRequest(**self.attributes["key_request"])

        if not self.client_id or not self.client_secret:
            raise ValueError(
                "AuthKeyManager.__init__: Could not fetch valid tailscale client id or secrets from SSM param store"
            )
        self.access_token = get_access_token(
            self.client_id, self.client_secret, self.tailnet
        )

    def create_secret(self):
        token: AuthToken = create_auth_key(self.access_token, self.key_request)
        attrs = dataclasses.asdict(token)
        attrs["key_request"] = dataclasses.asdict(self.key_request)
        return self._format_payload(attrs)

    def test_secret(self):
        try:
            auth_key_id = self.attributes["id"]
            auth_key = get_auth_key(self.access_token, auth_key_id)
            if auth_key.invalid:
                raise ValueError(f"testSecret: Auth key id={auth_key_id} is invalid")
        except HTTPError as e:
            if e.response.status_code == 404:
                raise ValueError(
                    f"testSecret: Key with id {auth_key_id} no longer exists!"
                )
            else:
                raise ValueError(
                    f"testSecret: Error happend while getting auth key with id={auth_key_id}"
                ) from e

    def finish_secret(self):
        pass
