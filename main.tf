data "aws_caller_identity" "current" {}
data "aws_region" "current" {}


#########################################################################################
# SSM Params for the lambda to consume
resource "aws_ssm_parameter" "ts_client_id" {
  count       = module.this.enabled ? 1 : 0
  name        = "/${module.this.id}/TS_CLIENT_ID"
  description = "Tailscale oauth client id for ${module.this.id}"
  type        = "SecureString"
  value       = var.ts_client_id
  key_id      = var.kms_key_arn != null ? var.kms_key_arn : null
  tags        = module.this.tags
}

resource "aws_ssm_parameter" "ts_client_secret" {
  count       = module.this.enabled ? 1 : 0
  name        = "/${module.this.id}/TS_CLIENT_SECRET"
  description = "Tailscale oauth client secret for ${module.this.id}"
  type        = "SecureString"
  value       = var.ts_client_secret
  key_id      = var.kms_key_arn != null ? var.kms_key_arn : null
  tags        = module.this.tags
}


#########################################################################################
# IAM resources

data "aws_iam_policy_document" "lambda" {
  statement {
    effect = "Allow"
    sid    = "AllowLambdaSSMParamAccess"
    actions = [
      "ssm:GetParameters",
      "ssm:GetParameter",
      "kms:Decrypt",
    ]
    resources = compact([
      aws_ssm_parameter.ts_client_id[0].arn,
      aws_ssm_parameter.ts_client_secret[0].arn,
      var.kms_key_arn
    ])

  }

  statement {
    effect = "Allow"
    sid    = "SecretsManagerActions"

    actions = [
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetSecretValue",
      "secretsmanager:PutSecretValue",
      "secretsmanager:UpdateSecretVersionStage"
    ]
    resources = [
      "arn:aws:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:${var.secret_prefix}"
    ]
    condition {
      test     = "StringEquals"
      variable = "secretsmanager:resource/AllowRotationLambdaArn"
      values   = [module.lambda[0].lambda_function_arn]

    }
  }
}

resource "aws_iam_policy" "lambda" {
  count       = module.this.enabled ? 1 : 0
  name        = module.this.id
  description = "Allow rotation of tailscale secrets"
  policy      = data.aws_iam_policy_document.lambda.json
}

resource "aws_iam_role_policy_attachment" "lambda" {
  count      = module.this.enabled ? 1 : 0
  role       = module.lambda[0].lambda_role_name
  policy_arn = aws_iam_policy.lambda[0].arn
}

#########################################################################################
# Lambda resources

module "package_lambda" {
  source  = "terraform-aws-modules/lambda/aws"
  version = "7.16.0"

  count = module.this.enabled ? 1 : 0

  create_function          = false
  recreate_missing_package = false

  build_in_docker = true
  runtime         = "python3.12"
  docker_image    = "build-ts-rotate-lambda"
  docker_file     = "${path.module}/Dockerfile"

  source_path = [
    "${path.module}/lambda/src",
    {
      path           = "${path.module}/lambda/pyproject.toml"
      poetry_install = true
      patterns = [
        "!.venv",
        "!.pytest_cache",
        "!.mypy_cache",
        "!__pycache__/?.*",
      ]
    }
  ]
  artifacts_dir = "${path.root}/builds/lambda-secrets-manager-tailscale-${module.this.id}/"
}

module "lambda" {
  source  = "terraform-aws-modules/lambda/aws"
  version = "7.16.0"
  count   = module.this.enabled ? 1 : 0

  function_name                     = module.this.id
  description                       = "Rotates Tailscale secrets via AWS SecretsManager"
  handler                           = "ts_rotate.handler.lambda_handler"
  runtime                           = "python3.12"
  timeout                           = 120
  local_existing_package            = module.package_lambda[0].local_filename
  create_package                    = false
  trusted_entities                  = ["secretsmanager.amazonaws.com"]
  cloudwatch_logs_kms_key_id        = var.kms_key_arn
  cloudwatch_logs_skip_destroy      = var.cloudwatch_logs_skip_destroy
  cloudwatch_logs_log_group_class   = var.cloudwatch_logs_log_group_class
  cloudwatch_logs_retention_in_days = var.cloudwatch_logs_retention_in_days

  environment_variables = {
    TS_CLIENT_ID_PARAM     = aws_ssm_parameter.ts_client_id[0].name
    TS_CLIENT_SECRET_PARAM = aws_ssm_parameter.ts_client_secret[0].name
    TS_TAILNET             = var.tailnet
  }
  tags = module.this.tags
}

resource "aws_lambda_alias" "default" {
  count            = module.this.enabled ? 1 : 0
  name             = "default"
  description      = "Use latest version as default"
  function_name    = module.lambda[0].lambda_function_name
  function_version = "$LATEST"
}

resource "aws_lambda_permission" "secretsmanager" {
  count         = module.this.enabled ? 1 : 0
  action        = "lambda:InvokeFunction"
  function_name = module.lambda[0].lambda_function_name
  principal     = "secretsmanager.amazonaws.com"
  statement_id  = "AllowExecutionFromSecretsManager1"
}
