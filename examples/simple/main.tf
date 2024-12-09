terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.0"
    }
  }
}

#############################################################################
# Tailscale Auth key
# The secrets-manager lambda module doesn't actually create the secrets manager resource
# you need to do that yourself
resource "aws_secretsmanager_secret" "authkey" {
  name                    = "${module.this.id}/tailscale3"
  recovery_window_in_days = 0
  tags                    = module.this.tags
}

resource "aws_secretsmanager_secret_rotation" "authkey" {
  secret_id           = aws_secretsmanager_secret.authkey.id
  rotation_lambda_arn = module.ts_rotate.lambda.lambda_function_arn

  rotation_rules {
    automatically_after_days = 1
  }
}

# You must initialize the secret with a TFINIT version_stage
# see the documentation for the format of this data structure
resource "aws_secretsmanager_secret_version" "authkey" {
  secret_id = aws_secretsmanager_secret.authkey.id
  secret_string = jsonencode({
    "Type" : "auth-key",
    "Attributes" : {
      "key_request" : {
        "tags" : [
          "tag:abel-poc-test"
        ],
        "description" : "a test",
        "expiry_seconds" : 120,
        "reusable" : true,
        "ephemeral" : true
      }
  } })
  version_stages = ["TFINIT"]
  depends_on = [
    module.ts_rotate.lambda
  ]
}

#############################################################################
# Rotation Lambda
module "ts_rotate" {
  source           = "../../"
  ts_client_secret = var.ts_client_secret
  ts_client_id     = var.ts_client_id
  tailnet          = var.tailnet
  secret_prefix    = "${module.this.id}/*"
  context          = module.this.context
}
