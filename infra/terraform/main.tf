data "aws_caller_identity" "current" {}

resource "aws_security_group" "load_balancer" {
  name_prefix = "${var.name}-alb-"
  description = "Allowlisted TLS ingress to the internal gateway"
  vpc_id      = var.vpc_id

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "gateway" {
  name_prefix = "${var.name}-gateway-"
  description = "Gateway task network boundary"
  vpc_id      = var.vpc_id

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "database" {
  name_prefix = "${var.name}-database-"
  description = "Database access from gateway tasks only"
  vpc_id      = var.vpc_id

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "load_balancer_https" {
  for_each          = toset(var.allowed_cidr_blocks)
  security_group_id = aws_security_group.load_balancer.id
  description       = "Private HTTPS clients"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_egress_rule" "load_balancer_gateway" {
  security_group_id            = aws_security_group.load_balancer.id
  description                  = "Gateway tasks"
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
  referenced_security_group_id = aws_security_group.gateway.id
}

resource "aws_vpc_security_group_ingress_rule" "gateway_load_balancer" {
  security_group_id            = aws_security_group.gateway.id
  description                  = "Internal load balancer"
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
  referenced_security_group_id = aws_security_group.load_balancer.id
}

resource "aws_vpc_security_group_egress_rule" "gateway_https" {
  security_group_id = aws_security_group.gateway.id
  description       = "TLS to private model and AWS endpoints"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "gateway_database" {
  security_group_id            = aws_security_group.gateway.id
  description                  = "PostgreSQL"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = aws_security_group.database.id
}

resource "aws_vpc_security_group_ingress_rule" "database_gateway" {
  security_group_id            = aws_security_group.database.id
  description                  = "PostgreSQL from gateway"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = aws_security_group.gateway.id
}

resource "aws_db_subnet_group" "database" {
  name       = "${var.name}-database"
  subnet_ids = var.private_subnet_ids
}

resource "aws_db_instance" "database" {
  identifier                   = "${var.name}-postgres"
  engine                       = "postgres"
  engine_version               = "16"
  instance_class               = var.database_instance_class
  allocated_storage            = 50
  max_allocated_storage        = 500
  storage_type                 = "gp3"
  storage_encrypted            = true
  kms_key_id                   = var.kms_key_arn
  db_name                      = "aegis"
  username                     = "aegis_admin"
  manage_master_user_password  = true
  db_subnet_group_name         = aws_db_subnet_group.database.name
  vpc_security_group_ids       = [aws_security_group.database.id]
  publicly_accessible          = false
  multi_az                     = true
  backup_retention_period      = 14
  deletion_protection          = true
  skip_final_snapshot          = false
  final_snapshot_identifier    = "${var.name}-final"
  performance_insights_enabled = true
  auto_minor_version_upgrade   = true
  apply_immediately            = false

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_cloudwatch_log_group" "gateway" {
  name              = "/ecs/${var.name}-gateway"
  retention_in_days = 90
  kms_key_id        = var.kms_key_arn
}

resource "aws_ecs_cluster" "gateway" {
  name = "${var.name}-gateway"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

data "aws_iam_policy_document" "task_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name_prefix        = "${var.name}-execution-"
  assume_role_policy = data.aws_iam_policy_document.task_assume.json
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "runtime_secrets" {
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.runtime_secret_arn]
  }

  dynamic "statement" {
    for_each = var.kms_key_arn == null ? [] : [var.kms_key_arn]
    content {
      actions   = ["kms:Decrypt"]
      resources = [statement.value]
    }
  }
}

resource "aws_iam_role_policy" "runtime_secrets" {
  name   = "runtime-secrets"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.runtime_secrets.json
}

resource "aws_iam_role" "task" {
  name_prefix        = "${var.name}-task-"
  assume_role_policy = data.aws_iam_policy_document.task_assume.json
}

resource "aws_ecs_task_definition" "gateway" {
  family                   = "${var.name}-gateway"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }

  container_definitions = jsonencode([
    {
      name                   = "gateway"
      image                  = var.image_uri
      essential              = true
      readonlyRootFilesystem = true
      user                   = "10001:10001"
      portMappings = [{
        name          = "http"
        containerPort = 8080
        protocol      = "tcp"
      }]
      environment = [
        { name = "AEGIS_ENVIRONMENT", value = "production" },
        { name = "AEGIS_PERSISTENCE", value = "postgres" },
        { name = "AEGIS_MODEL_PROVIDER", value = "openai-compatible" },
        { name = "AEGIS_MODEL_BASE_URL", value = var.model_base_url },
        { name = "AEGIS_MODEL_NAME", value = var.model_name },
      ]
      secrets = [
        { name = "AEGIS_DATABASE_URL", valueFrom = "${var.runtime_secret_arn}:AEGIS_DATABASE_URL::" },
        { name = "AEGIS_JWT_SECRET", valueFrom = "${var.runtime_secret_arn}:AEGIS_JWT_SECRET::" },
        { name = "AEGIS_AUDIT_HMAC_KEY", valueFrom = "${var.runtime_secret_arn}:AEGIS_AUDIT_HMAC_KEY::" },
        { name = "AEGIS_MODEL_API_KEY", valueFrom = "${var.runtime_secret_arn}:AEGIS_MODEL_API_KEY::" },
      ]
      linuxParameters = {
        capabilities       = { drop = ["ALL"] }
        initProcessEnabled = true
      }
      healthCheck = {
        command     = ["CMD-SHELL", "python -c \"import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/v1/health/live', timeout=2)\""]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 15
      }
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.gateway.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "gateway"
        }
      }
    }
  ])
}

resource "aws_lb" "gateway" {
  name                       = "${var.name}-gateway"
  internal                   = true
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.load_balancer.id]
  subnets                    = var.private_subnet_ids
  drop_invalid_header_fields = true
  enable_deletion_protection = true
}

resource "aws_lb_target_group" "gateway" {
  name        = "${var.name}-gateway"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    path                = "/v1/health/ready"
    matcher             = "200"
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.gateway.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.gateway.arn
  }
}

resource "aws_ecs_service" "gateway" {
  name            = "${var.name}-gateway"
  cluster         = aws_ecs_cluster.gateway.id
  task_definition = aws_ecs_task_definition.gateway.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.gateway.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.gateway.arn
    container_name   = "gateway"
    container_port   = 8080
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  depends_on = [aws_lb_listener.https]
}

resource "aws_appautoscaling_target" "gateway" {
  max_capacity       = 12
  min_capacity       = var.desired_count
  resource_id        = "service/${aws_ecs_cluster.gateway.name}/${aws_ecs_service.gateway.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "cpu" {
  name               = "${var.name}-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.gateway.resource_id
  scalable_dimension = aws_appautoscaling_target.gateway.scalable_dimension
  service_namespace  = aws_appautoscaling_target.gateway.service_namespace

  target_tracking_scaling_policy_configuration {
    target_value       = 65
    scale_in_cooldown  = 300
    scale_out_cooldown = 60

    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
  }
}
