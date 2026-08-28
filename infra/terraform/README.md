# Private AWS reference deployment

This module deploys the gateway as a private, multi-AZ ECS/Fargate service behind an
internal TLS load balancer, with encrypted PostgreSQL, autoscaling, deployment rollback,
90-day logs, and narrowly scoped task identities.

It intentionally consumes an existing VPC and private subnets so network ownership stays
with the platform team. Tasks receive no public IP. Provide NAT or private VPC endpoints
for the container registry, logs, secrets, and the approved model endpoint.

## Secret contract

Create the Secrets Manager resource outside this module and populate these JSON keys:

```json
{
  "AEGIS_DATABASE_URL": "postgresql://runtime:...@private-endpoint:5432/aegis",
  "AEGIS_JWT_SECRET": "independently-generated-value",
  "AEGIS_AUDIT_HMAC_KEY": "different-independently-generated-value",
  "AEGIS_MODEL_API_KEY": "provider-value-or-empty"
}
```

Keeping secret creation separate prevents values from entering Terraform state. Use the
AWS-managed database master secret only to run migrations and create the least-privilege
runtime database identity described in `migrations/002_database_roles.sql`.

## Apply

```bash
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform fmt -check
terraform validate
terraform plan -out=tfplan
terraform apply tfplan
```

The image variable requires a digest, not a mutable tag. Database and load balancer
deletion protection are enabled, and Terraform is prevented from destroying the database.
For an intentional teardown, preserve a final snapshot and explicitly change both guards
through a reviewed change.

