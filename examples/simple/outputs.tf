output "auth_key_arn" {
  value = aws_secretsmanager_secret.authkey.arn
}

output "lambda" {
  value = module.ts_rotate.lambda
}
