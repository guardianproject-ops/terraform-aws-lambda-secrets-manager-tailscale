output "lambda" {
  value = try(module.lambda[0], "")

  depends_on = [
    # the policy must be attached before the lambda is usable
    aws_iam_role_policy_attachment.lambda,
    # secretsmanager must have permission before the lambda is usable
    aws_lambda_permission.secretsmanager
  ]
}
