variable "aws_region" {
  description = "AWS region for all resources."
  type        = string
}

variable "name" {
  description = "Resource name prefix."
  type        = string
  default     = "aegis"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,30}$", var.name))
    error_message = "name must be a lowercase DNS-compatible identifier."
  }
}

variable "vpc_id" {
  description = "Existing VPC for the internal load balancer, tasks, and database."
  type        = string
}

variable "private_subnet_ids" {
  description = "At least two private subnet IDs in distinct availability zones."
  type        = list(string)

  validation {
    condition     = length(var.private_subnet_ids) >= 2
    error_message = "at least two private subnets are required."
  }
}

variable "allowed_cidr_blocks" {
  description = "Private network CIDRs allowed to reach the internal HTTPS listener."
  type        = list(string)

  validation {
    condition     = length(var.allowed_cidr_blocks) > 0
    error_message = "at least one allowlisted CIDR is required."
  }
}

variable "certificate_arn" {
  description = "ACM certificate ARN for the internal load balancer."
  type        = string
}

variable "image_uri" {
  description = "Immutable container image URI, preferably pinned by digest."
  type        = string

  validation {
    condition     = strcontains(var.image_uri, "@sha256:")
    error_message = "image_uri must be pinned to a sha256 digest."
  }
}

variable "runtime_secret_arn" {
  description = "Secrets Manager JSON secret containing runtime configuration."
  type        = string
}

variable "model_base_url" {
  description = "Private compatible model endpoint reachable from the task subnets."
  type        = string
}

variable "model_name" {
  description = "Approved model deployment name."
  type        = string
}

variable "desired_count" {
  description = "Steady-state gateway task count."
  type        = number
  default     = 3
}

variable "database_instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t4g.medium"
}

variable "kms_key_arn" {
  description = "Optional customer-managed KMS key for logs, secrets, and RDS."
  type        = string
  default     = null
}

variable "tags" {
  description = "Additional resource tags."
  type        = map(string)
  default     = {}
}

