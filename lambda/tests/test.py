import logging
import pprint
import sys
import time
from datetime import datetime

import ts_rotate.common
import ts_rotate.tailscale
from ts_rotate.tailscale import AuthKeyManager

# to run this script you will need to set some env-vars
# TS_CLIENT_ID_PARAM=/abel-testing-ts-client-id
# TS_CLIENT_SECRET_PARAM=/abel-testing-ts-client-secret
# TS_TAILNET=gpcmdln.net
# You should go create those SSM params in the AWS console and fill in a client id/secret (get it from tailscale's settings page)

#
# ! don't forget to delete them !
#


def main():
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    ttl = 30
    test_context = {
        "Type": "auth-key",
        "Attributes": {
            "key_request": {
                "tags": ["tag:abel-poc-test"],
                "description": "a test",
                "expiry_seconds": ttl,
                "reusable": True,
                "ephemeral": False,
            },
        },
    }

    logger.info("Creating AuthKeyManager...")
    manager = AuthKeyManager(test_context)

    logger.info("Creating auth key...")
    result = manager.create_secret()

    logger.info("Success! Auth key created:")
    pprint.pprint(result)

    manager = AuthKeyManager(result)
    manager.test_secret()

    print()
    print(f"Key validated. Sleeping {ttl/2}")
    print()

    time.sleep(ttl / 2)

    print()
    print(f"Key should still work...")
    manager = AuthKeyManager(result)
    manager.test_secret()
    print()
    print(f".. and it does. Sleeping {ttl/2+1}")
    time.sleep(1 + ttl / 2)
    print()
    print("TTL should have expired..")

    manager = AuthKeyManager(result)
    try:
        manager.test_secret()
        print("Failure! The key is still valid after the ttl has passed")
    except ValueError as e:
        print("Success!")


if __name__ == "__main__":
    sys.exit(main())

    """
 First create the secret
aws secretsmanager create-secret \
    --name "abel-test-tailscale-lambda" \
    --description "Tailscale auth key configuration"

# Then put the initial secret value
aws secretsmanager put-secret-value \
    --secret-id "abel-test-tailscale-lambda" \
    --secret-string '
{
  "Type": "auth-key",
  "Attributes": {
    "key_request": {
      "tags": [
        "tag:abel-poc-test"
      ],
      "description": "a test",
      "expiry_seconds": 3600,
      "reusable": true,
      "ephemeral": false
    }
  }
}
    '
    """
