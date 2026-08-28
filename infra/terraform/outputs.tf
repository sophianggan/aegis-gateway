output "gateway_dns_name" {
  description = "Internal load balancer DNS name."
  value       = aws_lb.gateway.dns_name
}

output "database_endpoint" {
  description = "Private PostgreSQL endpoint used when provisioning the runtime secret."
  value       = aws_db_instance.database.address
}

output "database_master_secret_arn" {
  description = "AWS-managed master secret used only for migration/user provisioning."
  value       = aws_db_instance.database.master_user_secret[0].secret_arn
  sensitive   = true
}

output "ecs_cluster_name" {
  description = "Cluster name for one-off migration tasks."
  value       = aws_ecs_cluster.gateway.name
}

output "ecs_service_name" {
  description = "Gateway service name."
  value       = aws_ecs_service.gateway.name
}

output "task_definition_arn" {
  description = "Task definition used for deployments and one-off migrations."
  value       = aws_ecs_task_definition.gateway.arn
}

