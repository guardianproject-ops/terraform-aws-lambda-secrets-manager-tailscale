variable "secret_prefix" {
  type        = string
  description = "The Secrets Manager Secret prefix of the secrets this lambda will manage, including the wild card if you want one. e.g., 'tailscale/*'"
}

variable "kms_key_arn" {
  type        = string
  default     = null
  description = "Optional KMS key to encrypt the oauth client id and secret in the SSM param store"
}

variable "tailnet" {
  type = string
}

variable "ts_client_id" {
  type      = string
  sensitive = true
}

variable "ts_client_secret" {
  type      = string
  sensitive = true
}

variable "cloudwatch_logs_skip_destroy" {
  description = "Whether to keep the log group (and any logs it may contain) at destroy time."
  type        = bool
  default     = false
}

variable "cloudwatch_logs_log_group_class" {
  description = "Specified the log class of the log group. Possible values are: `STANDARD` or `INFREQUENT_ACCESS`"
  type        = string
  default     = null
}
variable "cloudwatch_logs_retention_in_days" {
  description = "Specifies the number of days you want to retain log events in the specified log group. Possible values are: 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, and 3653."
  type        = number
  default     = null
}
