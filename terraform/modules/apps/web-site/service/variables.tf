variable "namespace" {
  type        = string
  description = "A namespace to depoy all resources under, prefixed to all names to avoid collision"
}

variable "name" {
  type        = string
  description = "The name of the ECS service"
}

variable "image_name" {
  type        = string
  description = "The name of the Docker image to deploy"
}

variable "image_tag" {
  type        = string
  description = "Tag of the image to deploy"
  default     = null
}

variable "cluster_arn" {
  type        = string
  description = "ARN of the ECS cluster"
}

variable "vpc_name" {
  type        = string
  description = "Name of the VPC to deploy into"
}

variable "desired_count" {
  type        = number
  description = "The number of instances of the task definition to place and keep running"
  default     = 1
}

variable "cpu" {
  type        = number
  description = "The number of CPU units used by the task. If using `FARGATE` launch type `task_cpu` must match [supported memory values](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html#task_size)"
}

variable "memory" {
  type        = number
  description = "The amount of memory (in MiB) used by the task. If using Fargate launch type `task_memory` must match [supported cpu value](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html#task_size)"
}

variable "cpu_architecture" {
  description = "CPU architecture that containers run on. Must be set to either X86_64 or ARM64"
  type        = string

  validation {
    condition     = contains(["X86_64", "ARM64"], var.cpu_architecture)
    error_message = "Valid values are `X86_64` and `ARM64`"
  }
}

variable "deployment_controller_type" {
  type        = string
  description = "Type of deployment controller. Valid values are `CODE_DEPLOY` and `ECS`"
  default     = "ECS"
}

variable "deployment_maximum_percent" {
  type        = number
  description = "The upper limit of the number of tasks (as a percentage of `desired_count`) that can be running in a service during a deployment"
  default     = 200
}

variable "deployment_minimum_healthy_percent" {
  type        = number
  description = "The lower limit (as a percentage of `desired_count`) of the number of tasks that must remain running and healthy in a service during a deployment"
  default     = 100
}

variable "health_check_grace_period_seconds" {
  type        = number
  description = "Seconds to ignore failing load balancer health checks on newly instantiated tasks to prevent premature shutdown, up to 7200. Only valid for services configured to use load balancers"
  default     = 0
}

variable "environment" {
  type        = string
  description = "Name of the deployment environment for tagging (beta, development, staging, production)"
}

variable "subdomain" {
  type        = string
  default     = null
  description = "The name of the DNS record to create in the subdomain"
}

variable "dns_hosted_zone" {
  type        = string
  description = "The name of the route53 hosted zone to create a DNS record in. The record will have the same name as the service name"
}

variable "internet_facing" {
  type        = bool
  default     = false
  description = "A boolean flag to determine whether the ALB should be internet facing"
}

variable "load_balancer_allow_cloudflare_ips" {
  type        = bool
  default     = false
  description = "Determine whether the ALB should only allow traffic from Cloudflare IPs"
}

variable "load_balancer_allow_vpn_ips" {
  type        = bool
  default     = false
  description = "Determine whether the ALB should allow traffic from VPN IPs. When set, public IPs will no longer be able to reach the ALB"
}

variable "task_policy_arns" {
  type        = map(string)
  description = <<-EOT
    A map of name to IAM Policy ARNs to attach to the generated task role.
    The names are arbitrary, but must be known at plan time. The purpose of the name
    is so that changes to one ARN do not cause a ripple effect on the other ARNs.
    EOT
  default     = {}
}

variable "external_certs" {
  type        = list(string)
  description = "Add additional certificates for external domain names to serve the service on. The ACM certificate must already have been issued"
  default     = []
}

variable "create_template_task_definition" {
  type        = bool
  description = "Whether to create a template task definition and expect an external CI system to update the service with a real task definition. If enabled, task definition changes will be ignored"
  default     = true
}
