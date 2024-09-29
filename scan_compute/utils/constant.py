"""Constants."""

from __future__ import annotations

AWS = "AWS"
AWS_RESOURCE_PATH = [
    {
        "display_path": "acm.regions.id.certificates.id",
        "resource_type": "AWS.ACM.Certificate",
    },
    {
        "display_path": "apigateway.regions.id.apiaccounts.id",
        "resource_type": "AWS.ApiGateway.RestApi",
    },
    {
        "display_path": "autoscaling.regions.id.autoscaling.id",
        "resource_type": "AWS.AutoScaling.AutoScalingGroup",
    },
    {
        "display_path": "athena.regions.id.query_executions.id",
        "resource_type": "AWS.Athena.QueryExecutions",
    },
    {
        "display_path": "awslambda.regions.id.functions.id",
        "resource_type": "AWS.Lambda.Function",
    },
    {
        "display_path": "cloudformation.regions.id.stacks.id",
        "resource_type": "AWS.CloudFormation.Stack",
    },
    {
        "display_path": "cloudfront.cloudfront.id",
        "resource_type": "AWS.CloudFront.Distribution",
    },
    {
        "display_path": "cloudtrail.regions.id.trails.id",
        "resource_type": "AWS.CloudTrail.Trail",
    },
    {
        "display_path": "cloudwatch.regions.id.alarms.id",
        "resource_type": "AWS.CloudWatch.Alarm",
    },
    {
        "display_path": "cloudwatch.regions.id.eventbridge.id",
        "resource_type": "AWS.CloudWatchEvents.Rule",
    },
    {
        "display_path": "cloudwatch.regions.id.eventbus.id",
        "resource_type": "AWS.Events.EventBus",
    },
    {
        "display_path": "cloudwatch.regions.id.log_groups.id",
        "resource_type": "AWS.CloudWatchLogs.LogGroup",
    },
    {
        "display_path": "cloudwatch.regions.id.metric_filters.id",
        "resource_type": "AWS.Logs.MetricFilter",
    },
    # {
    #     "display_path": "config.regions.id.recorders.id",
    #     "resource_type": "AWS.Config.ConfigurationRecorder"
    # },
    # {
    #     "display_path": "config.regions.id.deliverychannels.id",
    #     "resource_type": "AWS.Config.DeliveryChannel"
    # },
    # {
    #     "display_path": "config.regions.id.rules.id",
    #     "resource_type": "AWS.Config.ConfigRule"
    # },
    {
        "display_path": "cognito.regions.id.user_pools.id",
        "resource_type": "AWS.Cognito.UserPool",
    },
    {
        "display_path": "directconnect.regions.id.connections.id",
        "resource_type": "AWS.DirectConnect.Connections",
    },
    {
        "display_path": "dynamodb.regions.id.clusters.id",
        "resource_type": "AWS.DAX.Cluster",
    },
    {
        "display_path": "dynamodb.regions.id.tables.id",
        "resource_type": "AWS.DynamoDB.Table",
    },
    {
        "display_path": "ec2.regions.id.snapshots.id",
        "resource_type": "AWS.EC2.Snapshot",
    },
    {
        "display_path": "ec2.regions.id.images.id",
        "resource_type": "AWS.EC2.Ami",
    },
    {
        "display_path": "ec2.regions.id.volumes.id",
        "resource_type": "AWS.EC2.Volume",
    },
    {
        "display_path": "ec2.regions.id.vpcs.id.instances.id",
        "resource_type": "AWS.EC2.Instance",
    },
    {
        "display_path": "ec2.regions.id.vpcs.id.network_interfaces.id",
        "resource_type": "AWS.EC2.NetworkInterface",
    },
    {
        "display_path": "ec2.regions.id.vpcs.id.security_groups.id",
        "resource_type": "AWS.EC2.SecurityGroup",
    },
    {
        "display_path": "ec2.regions.id.account_attributes.id",
        "resource_type": "AWS.EC2.AccountAttributes",
    },
    {
        "display_path": "ec2.regions.id.key_pairs.id",
        "resource_type": "AWS.EC2.KeyPair",
    },
    {
        "display_path": "ecr.regions.id.repositories.id",
        "resource_type": "AWS.ECR.Repository",
    },
    {
        "display_path": "ecr.regions.id.policyText.id",
        "resource_type": "AWS.ECR.RepositoryPolicy",
    },
    {
        "display_path": "ecs.regions.id.clusters.id",
        "resource_type": "AWS.ECS.Cluster",
    },
    {
        "display_path": "ecs.regions.id.containerInstances.id",
        "resource_type": "AWS.ECS.ContainerInstances",
    },
    {
        "display_path": "ecs.regions.id.services.id",
        "resource_type": "AWS.ECS.Service",
    },
    {
        "display_path": "efs.regions.id.filesystems.id",
        "resource_type": "AWS.EFS.FileSystem",
    },
    {
        "display_path": "elasticache.regions.id.parameter_groups.id",
        "resource_type": "AWS.ElastiCache.ParameterGroup",
    },
    {
        "display_path": "elasticache.regions.id.replication_groups.id",
        "resource_type": "AWS.ElastiCache.ReplicationGroup",
    },
    {
        "display_path": "elasticache.regions.id.vpcs.id.clusters.id",
        "resource_type": "AWS.ElastiCache.Cluster",
    },
    {
        "display_path": "elasticbeanstalk.regions.id.configuration.id",
        "resource_type": "AWS.ElasticBeanstalk.Configuration",
    },
    {
        "display_path": "elasticbeanstalk.regions.id.environments.id",
        "resource_type": "AWS.ElasticBeanstalk.Environment",
    },
    {
        "display_path": "elb.regions.id.elb_policies.id",
        "resource_type": "AWS.ELB.Policy",
    },
    {
        "display_path": "elb.regions.id.vpcs.id.elbs.id",
        "resource_type": "AWS.ELB.LoadBalancer",
    },
    {
        "display_path": "elbv2.regions.id.vpcs.id.lbs.id",
        "resource_type": "AWS.ELBv2.LoadBalancer",
    },
    {
        "display_path": "emr.regions.id.vpcs.id.clusters.id",
        "resource_type": "AWS.EMR.Cluster",
    },
    {
        "display_path": "eks.regions.id.clusters.id",
        "resource_type": "AWS.EKS.Cluster",
    },
    {
        "display_path": "glue.regions.id.data_catalog_encryption_settings.id",
        "resource_type": "AWS.Glue.DataCatalogEncryptionSettings",
    },
    {
        "display_path": "glue.regions.id.security_configuration.id",
        "resource_type": "AWS.Glue.SecurityConfiguration",
    },
    {
        "display_path": "iam.certificates.id",
        "resource_type": "AWS.IAM.ServerCertificate",
    },
    {
        "display_path": "iam.credential_reports.id",
        "resource_type": "AWS.IAM.CredentialReport",
    },
    {
        "display_path": "iam.root_user_credential_report.id",
        "resource_type": "AWS.IAM.CredentialReport",
    },
    {
        "display_path": "iam.groups.id",
        "resource_type": "AWS.IAM.Group",
    },
    {
        "display_path": "iam.password_policy",
        "resource_type": "AWS.IAM.AccountPasswordPolicy",
    },
    {
        "display_path": "iam.policies.id",
        "resource_type": "AWS.IAM.Policy",
    },
    {"display_path": "iam.roles.id", "resource_type": "AWS.IAM.Role"},
    {"display_path": "iam.users.id", "resource_type": "AWS.IAM.User"},
    {
        "display_path": "iam.support_policy.id",
        "resource_type": "AWS.IAM.SupportPolicy",
    },
    {
        "display_path": "kinesis.regions.id.KinesisStreams.id",
        "resource_type": "AWS.Kinesis.Stream",
    },
    {
        "display_path": "kms.regions.id.keys.id",
        "resource_type": "AWS.KMS.Key",
    },
    {
        "display_path": "neptune.regions.id.dbinstances.id",
        "resource_type": "AWS.Neptune.DBInstance",
    },
    {
        "display_path": "organization.listaccounts.id",
        "resource_type": "AWS.Organizations.Organization",
    },
    {
        "display_path": "rds.regions.id.events.id",
        "resource_type": "AWS.RDS.EventSubscription",
    },
    {
        "display_path": "rds.regions.id.vpcs.id.instances.id",
        "resource_type": "AWS.RDS.Instance",
    },
    {
        "display_path": "rds.regions.id.vpcs.id.cluster.id",
        "resource_type": "AWS.RDS.Cluster",
    },
    {
        "display_path": "rds.regions.id.vpcs.id.snapshots.id",
        "resource_type": "AWS.RDS.Snapshot",
    },
    {
        "display_path": "rds.regions.id.reserved_instances.id",
        "resource_type": "AWS.RDS.ReservedInstance",
    },
    {
        "display_path": "redshift.regions.id.parameter_groups.id",
        "resource_type": "AWS.Redshift.ParameterGroup",
    },
    {
        "display_path": "redshift.regions.id.vpcs.id.clusters.id",
        "resource_type": "AWS.Redshift.Cluster",
    },
    {
        "display_path": "route53.regions.id.domains.id",
        "resource_type": "AWS.Route53.Domains",
    },
    {
        "display_path": "route53.regions.id.hosted_zones.id",
        "resource_type": "AWS.Route53.HostedZone",
    },
    {
        "display_path": "sagemaker.regions.id.notebook_instances.id",
        "resource_type": "AWS.Sagemaker.NotebookInstance",
    },
    {
        "display_path": "s3.buckets.id",
        "resource_type": "AWS.S3.Bucket",
    },
    {
        "display_path": "s3.public_access_block_configuration",
        "resource_type": "AWS.S3.PublicAccessBlockConfiguration",
    },
    {
        "display_path": "secretsmanager.regions.id.secrets.id",
        "resource_type": "AWS.SecretsManager.Secret",
    },
    {
        "display_path": "ses.regions.id.identities.id",
        "resource_type": "AWS.SES.Identities",
    },
    {
        "display_path": "sns.regions.id.topics.id",
        "resource_type": "AWS.SNS.Topic",
    },
    {
        "display_path": "sqs.regions.id.queues.id",
        "resource_type": "AWS.SQS.Queue",
    },
    {
        "display_path": "stepfunctions.regions.id.stateMachine.id",
        "resource_type": "AWS.SFN.StateMachine",
    },
    {
        "display_path": "vpc.regions.id.egress_internet_gateways.id",
        "resource_type": "AWS.EC2.EgressOnlyInternetGateway",
    },
    {
        "display_path": "vpc.regions.id.internet_gateways.id",
        "resource_type": "AWS.EC2.InternetGateway",
    },
    {
        "display_path": "vpc.regions.id.nat_gateways.id",
        "resource_type": "AWS.EC2.NATGateway",
    },
    {
        "display_path": "vpc.regions.id.nat_zones.id",
        "resource_type": "AWS.EC2.NATZones",
    },
    {
        "display_path": "vpc.regions.id.peering_connections.id",
        "resource_type": "AWS.EC2.VpcPeeringConnection",
    },
    {
        "display_path": "vpc.regions.id.vpcs.id",
        "resource_type": "AWS.EC2.Vpc",
    },
    {
        "display_path": "vpc.regions.id.vpcs.id.network_acls.id",
        "resource_type": "AWS.EC2.NetworkACL",
    },
    {
        "display_path": "vpc.regions.id.vpcs.id.subnets.id",
        "resource_type": "AWS.EC2.Subnet",
    },
    {
        "display_path": "vpc.regions.id.vpn_gateways.id",
        "resource_type": "AWS.EC2.VpnGateway",
    },
    {
        "display_path": "vpc.regions.id.route_tables.id",
        "resource_type": "AWS.EC2.RouteTable",
    },
    {
        "display_path": "vpc.regions.id.flow_logs.id",
        "resource_type": "AWS.EC2.FlowLog",
    },
    {
        "display_path": "vpc.regions.id.vpns.id",
        "resource_type": "AWS.EC2.VpnConnection",
    },
    {
        "display_path": "vpc.regions.id.vpcs.id.endpoints.id",
        "resource_type": "AWS.EC2.VpcEndpoint",
    },
    {
        "display_path": "waf.regions.id.web_acls.id",
        "resource_type": "AWS.WAF.WebACL",
    },
    {
        "display_path": "wafv2.regions.id.web_acls.id",
        "resource_type": "AWS.WAFv2.WebACL",
    },
    {
        "display_path": "neptune.regions.id.snapshots.id",
        "resource_type": "AWS.Neptune.Snapshot",
    },
    {
        "display_path": "backup.regions.id.plans.id",
        "resource_type": "AWS.Backup.Plan",
    },
    {
        "display_path": "backup.regions.id.vaults.id",
        "resource_type": "AWS.Backup.Vault",
    },
]
AWS_DISPLAY_PATH = [
    "acm.regions.id.certificates.id",
    "apigateway.regions.id.apiaccounts.id",
    "autoscaling.regions.id.autoscaling.id",
    "athena.regions.id.query_executions.id",
    "awslambda.regions.id.functions.id",
    "cloudformation.regions.id.stacks.id",
    "cloudfront.cloudfront.id",
    "cloudtrail.regions.id.trails.id",
    "cloudwatch.regions.id.alarms.id",
    "cloudwatch.regions.id.eventbridge.id",
    "cloudwatch.regions.id.eventbus.id",
    "cloudwatch.regions.id.log_groups.id",
    "cloudwatch.regions.id.metric_filters.id",
    "cognito.regions.id.user_pools.id",
    "directconnect.regions.id.connections.id",
    "dynamodb.regions.id.clusters.id",
    "dynamodb.regions.id.tables.id",
    "ec2.regions.id.snapshots.id",
    "ec2.regions.id.images.id",
    "ec2.regions.id.volumes.id",
    "ec2.regions.id.vpcs.id.instances.id",
    "ec2.regions.id.vpcs.id.network_interfaces.id",
    "ec2.regions.id.vpcs.id.security_groups.id",
    "ec2.regions.id.account_attributes.id",
    "ec2.regions.id.key_pairs.id",
    "ecr.regions.id.repositories.id",
    "ecr.regions.id.policyText.id",
    "ecs.regions.id.clusters.id",
    "ecs.regions.id.containerInstances.id",
    "ecs.regions.id.services.id",
    "efs.regions.id.filesystems.id",
    "elasticache.regions.id.parameter_groups.id",
    "elasticache.regions.id.replication_groups.id",
    "elasticache.regions.id.vpcs.id.clusters.id",
    "elasticbeanstalk.regions.id.configuration.id",
    "elasticbeanstalk.regions.id.environments.id",
    "elb.regions.id.elb_policies.id",
    "elb.regions.id.vpcs.id.elbs.id",
    "elbv2.regions.id.vpcs.id.lbs.id",
    "emr.regions.id.vpcs.id.clusters.id",
    "eks.regions.id.clusters.id",
    "glue.regions.id.data_catalog_encryption_settings.id",
    "glue.regions.id.security_configuration.id",
    "iam.certificates.id",
    "iam.credential_reports.id",
    "iam.root_user_credential_report.id",
    "iam.groups.id",
    "iam.password_policy",
    "iam.policies.id",
    "iam.roles.id",
    "iam.users.id",
    "iam.support_policy.id",
    "kinesis.regions.id.KinesisStreams.id",
    "kms.regions.id.keys.id",
    "neptune.regions.id.dbinstances.id",
    "organization.listaccounts.id",
    "rds.regions.id.events.id",
    "rds.regions.id.vpcs.id.instances.id",
    "rds.regions.id.vpcs.id.cluster.id",
    "rds.regions.id.vpcs.id.snapshots.id",
    "rds.regions.id.reserved_instances.id",
    "redshift.regions.id.parameter_groups.id",
    "redshift.regions.id.vpcs.id.clusters.id",
    "route53.regions.id.domains.id",
    "route53.regions.id.hosted_zones.id",
    "sagemaker.regions.id.notebook_instances.id",
    "s3.buckets.id",
    "s3.public_access_block_configuration",
    "secretsmanager.regions.id.secrets.id",
    "ses.regions.id.identities.id",
    "sns.regions.id.topics.id",
    "sqs.regions.id.queues.id",
    "stepfunctions.regions.id.stateMachine.id",
    "vpc.regions.id.egress_internet_gateways.id",
    "vpc.regions.id.internet_gateways.id",
    "vpc.regions.id.nat_gateways.id",
    # "vpc.regions.id.nat_zones.id",
    "vpc.regions.id.peering_connections.id",
    "vpc.regions.id.vpcs.id",
    "vpc.regions.id.vpcs.id.network_acls.id",
    "vpc.regions.id.vpcs.id.subnets.id",
    "vpc.regions.id.vpn_gateways.id",
    "vpc.regions.id.route_tables.id",
    "vpc.regions.id.flow_logs.id",
    "vpc.regions.id.vpns.id",
    "vpc.regions.id.vpcs.id.endpoints.id",
    "waf.regions.id.web_acls.id",
    "wafv2.regions.id.web_acls.id",
    "neptune.regions.id.snapshots.id",
    "backup.regions.id.plans.id",
    "backup.regions.id.vaults.id",
]
AWS_RESOURCE_TYPE: list[str] = []
AWS_REGIONS_KEY = "regions"
AWS_REGIONS = [
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-south-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "ca-central-1",
    "eu-central-1",
    "eu-north-1",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "sa-east-1",
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
]
AWS_RTM_SERVICES_LIST = [
    "acm",
    "apigateway",
    "athena",
    "autoscaling",
    "cloudformation",
    "cloudfront",
    "cloudtrail",
    "logs",
    "cognito-identity",
    "cognito-idp",
    "cognito-sync",
    "config",
    "dax",
    "directconnect",
    "dynamodb",
    "ec2",
    "ecr",
    "ecs",
    "eks",
    "elasticache",
    "elasticbeanstalk",
    "elasticfilesystem",
    "elasticloadbalancing",
    "elasticloadbalancingv2",
    "elasticmapreduce",
    "events",
    "glue",
    "iam",
    "kinesis",
    "kms",
    "lambda",
    "neptune",
    "organizations",
    "rds",
    "redshift",
    "route53",
    "s3",
    "sagemaker",
    "secretsmanager",
    "ses",
    "sns",
    "sqs",
    "states",
    "vpc",
    "waf",
    "wafv2",
]
AWS_RTM_SERVICES = [
    {
        "rtm_service": "acm",
        "rule_db_service": "ACM",
        "scanner_service": "acm",
    },
    {
        "rtm_service": "apigateway",
        "rule_db_service": "APIGateway",
        "scanner_service": "apigateway",
    },
    {
        "rtm_service": "athena",
        "rule_db_service": "No Service",
        "scanner_service": "athena",
    },
    {
        "rtm_service": "autoscaling",
        "rule_db_service": "AutoScaling",
        "scanner_service": "autoscaling",
    },
    {
        "rtm_service": "cloudformation",
        "rule_db_service": "CloudFormation",
        "scanner_service": "cloudformation",
    },
    {
        "rtm_service": "cloudfront",
        "rule_db_service": "Cloudfront",
        "scanner_service": "cloudfront",
    },
    {
        "rtm_service": "cloudtrail",
        "rule_db_service": "Cloudtrail",
        "scanner_service": "cloudtrail",
    },
    {
        "rtm_service": "logs",
        "rule_db_service": "Cloudwatch",
        "scanner_service": "cloudwatch",
    },
    {
        "rtm_service": "cognito-identity",
        "rule_db_service": "No Service",
        "scanner_service": "cognito",
    },
    {
        "rtm_service": "cognito-idp",
        "rule_db_service": "No Service",
        "scanner_service": "cognito",
    },
    {
        "rtm_service": "cognito-sync",
        "rule_db_service": "No Service",
        "scanner_service": "cognito",
    },
    {
        "rtm_service": "config",
        "rule_db_service": "No Service",
        "scanner_service": "config",
    },
    {
        "rtm_service": "dax",
        "rule_db_service": "DynamoDB",
        "scanner_service": "dynamodb",
    },
    {
        "rtm_service": "directconnect",
        "rule_db_service": "No Service",
        "scanner_service": "directconnect",
    },
    {
        "rtm_service": "dynamodb",
        "rule_db_service": "DynamoDB",
        "scanner_service": "dynamodb",
    },
    {
        "rtm_service": "ec2",
        "rule_db_service": "EC2",
        "scanner_service": "ec2",
    },
    {
        "rtm_service": "ecr",
        "rule_db_service": "ECR",
        "scanner_service": "ecr",
    },
    {
        "rtm_service": "ecs",
        "rule_db_service": "ECS",
        "scanner_service": "ecs",
    },
    {
        "rtm_service": "eks",
        "rule_db_service": "No Service",
        "scanner_service": "eks",
    },
    {
        "rtm_service": "elasticache",
        "rule_db_service": "ElastiCache",
        "scanner_service": "elasticache",
    },
    {
        "rtm_service": "elasticbeanstalk",
        "rule_db_service": "Beanstalk",
        "scanner_service": "elasticbeanstalk",
    },
    {
        "rtm_service": "elasticfilesystem",
        "rule_db_service": "EFS",
        "scanner_service": "efs",
    },
    {
        "rtm_service": "elasticloadbalancing",
        "rule_db_service": "ELB",
        "scanner_service": "elb",
    },
    {
        "rtm_service": "elasticloadbalancingv2",
        "rule_db_service": "ELBv2",
        "scanner_service": "elbv2",
    },
    {
        "rtm_service": "elasticmapreduce",
        "rule_db_service": "EMR",
        "scanner_service": "emr",
    },
    {
        "rtm_service": "events",
        "rule_db_service": "Cloudwatch",
        "scanner_service": "cloudwatch",
    },
    {
        "rtm_service": "glue",
        "rule_db_service": "Glue",
        "scanner_service": "glue",
    },
    {
        "rtm_service": "iam",
        "rule_db_service": "IAM",
        "scanner_service": "iam",
    },
    {
        "rtm_service": "kinesis",
        "rule_db_service": "No Service",
        "scanner_service": "kinesis",
    },
    {
        "rtm_service": "kms",
        "rule_db_service": "KMS",
        "scanner_service": "kms",
    },
    {
        "rtm_service": "lambda",
        "rule_db_service": "Lambda",
        "scanner_service": "awslambda",
    },
    {
        "rtm_service": "neptune",
        "rule_db_service": "No Service",
        "scanner_service": "neptune",
    },
    {
        "rtm_service": "organizations",
        "rule_db_service": "Organizations",
        "scanner_service": "organization",
    },
    {
        "rtm_service": "rds",
        "rule_db_service": "RDS",
        "scanner_service": "rds",
    },
    {
        "rtm_service": "redshift",
        "rule_db_service": "Redshift",
        "scanner_service": "redshift",
    },
    {
        "rtm_service": "route53",
        "rule_db_service": "Route53",
        "scanner_service": "route53",
    },
    {
        "rtm_service": "s3",
        "rule_db_service": "S3",
        "scanner_service": "s3",
    },
    {
        "rtm_service": "sagemaker",
        "rule_db_service": "No Service",
        "scanner_service": "sagemaker",
    },
    {
        "rtm_service": "secretsmanager",
        "rule_db_service": "SecretsManager",
        "scanner_service": "secretsmanager",
    },
    {
        "rtm_service": "ses",
        "rule_db_service": "SES",
        "scanner_service": "ses",
    },
    {
        "rtm_service": "sns",
        "rule_db_service": "SNS",
        "scanner_service": "sns",
    },
    {
        "rtm_service": "sqs",
        "rule_db_service": "SQS",
        "scanner_service": "sqs",
    },
    {
        "rtm_service": "states",
        "rule_db_service": "SFN",
        "scanner_service": "stepfunctions",
    },
    {
        "rtm_service": "vpc",
        "rule_db_service": "VPC",
        "scanner_service": "vpc",
    },
    {
        "rtm_service": "waf",
        "rule_db_service": "WAF",
        "scanner_service": "waf",
    },
    {
        "rtm_service": "wafv2",
        "rule_db_service": "WAFv2",
        "scanner_service": "wafv2",
    },
]

GCP = "GCP"
GCP_RESOURCE_PATH = [
    {
        "display_path": "iam.projects.id.service_accounts.id",
        "resource_type": "GCP.IAM.ServiceAccount",
    },
    {
        "display_path": "iam.projects.id.bindings.id",
        "resource_type": "GCP.IAM.Policy",
    },
    {
        "display_path": "iam.projects.id.users.id",
        "resource_type": "GCP.IAM.User",
    },
    {
        "display_path": "kms.projects.id.keyrings.id",
        "resource_type": "GCP.KMS.Keys",
    },
    {
        "display_path": "serviceusage.projects.id.apikeys.id",
        "resource_type": "GCP.SU.ApiKeys",
    },
    {
        "display_path": "serviceusage.projects.id.services.id",
        "resource_type": "GCP.SU.Services",
    },
    {
        "display_path": "stackdriverlogging.projects.id.sinks.id",
        "resource_type": "GCP.CLO.Sink",
    },
    {
        "display_path": "stackdriverlogging.projects.id",
        "resource_type": "GCP.CLO.Logging",
    },
    {
        "display_path": "stackdriverlogging.projects.id.logging_metrics.id",
        "resource_type": "GCP.CLO.MetricFilter",
    },
    {
        "display_path": "dns.projects.id.policies.id",
        "resource_type": "GCP.DNS.Policy",
    },
    {
        "display_path": "dns.projects.id.managed_zones.id",
        "resource_type": "GCP.DNS.Zone",
    },
    {
        "display_path": "computeengine.projects.id.regions.id.subnetworks.id",
        "resource_type": "GCP.GCE.Subnetwork",
    },
    {
        "display_path": "computeengine.projects.id.zones.id.instances.id",
        "resource_type": "GCP.GCE.Instance",
    },
    {
        "display_path": "cloudstorage.projects.id.buckets.id",
        "resource_type": "GCP.STO.Bucket",
    },
    {
        "display_path": "cloudsql.projects.id.instances.id",
        "resource_type": "GCP.SQL.Instance",
    },
    {
        "display_path": "iam.projects.id.bindings_separation_duties.id",
        "resource_type": "GCP.IAM.BindingSeparationDuties",
    },
    {
        "display_path": "dataproc.projects.id.regions.id.clusters.id",
        "resource_type": "GCP.DPR.Cluster",
    },
    {
        "display_path": "bigquery.projects.id.datasets.id",
        "resource_type": "GCP.BQ.Dataset",
    },
    {
        "display_path": "computeengine.projects.id.networks.id",
        "resource_type": "GCP.GCE.Network",
    },
    {
        "display_path": "bigquery.projects.id.datasets.id.tables.id",
        "resource_type": "GCP.BQ.Table",
    },
    {
        "display_path": "loadbalancing.projects.id.load_balancers.id",
        "resource_type": "GCP.CLB.LoandBalancer",
    },
    {
        "display_path": "pubsub.projects.id.topics.id.subscriptions.id",
        "resource_type": "GCP.PUS.Subscription",
    },
    {
        "display_path": "pubsub.projects.id.topics.id",
        "resource_type": "GCP.PUS.Topic",
    },
    {
        "display_path": "functions.projects.id.functions_v1.id",
        "resource_type": "GCP.GCFv1.Function",
    },
    {
        "display_path": "functions.projects.id.functions_v2.id",
        "resource_type": "GCP.GCFv2.Function",
    },
    {
        "display_path": "computeengine.projects.id.firewalls.id",
        "resource_type": "GCP.GCE.Firewall",
    },
    {
        "display_path": "stackdrivermonitoring.projects.id.monitoring_alert_policies.id",
        "resource_type": "GCP.CLO.MonitoringAlertPolicy",
    },
    {
        "display_path": "computeengine.projects.id.snapshots.id",
        "resource_type": "GCP.GCE.Snapshot",
    },
    {
        "display_path": "computeengine.projects.id.zones.id.instances.id.disks.id",
        "resource_type": "GCP.GCE.Disk",
    },
    {
        "display_path": "cloudmemorystore.projects.id.redis_instances.id",
        "resource_type": "GCP.CMS.RedisInstance",
    },
    {
        "display_path": "kubernetesengine.projects.id.zones.id.clusters.id",
        "resource_type": "GCP.GKE.Node",
    },
    {
        "display_path": "cloudrun.projects.id.services.id",
        "resource_type": "GCP.CLR.Service",
    },
    {
        "display_path": "artifactregistry.projects.id.repositories.id",
        "resource_type": "GCP.GAR.Repository",
    },
]
GCP_DISPLAY_PATH = [
    "iam.projects.id.service_accounts.id",
    "iam.projects.id.bindings.id",
    "iam.projects.id.users.id",
    "kms.projects.id.keyrings.id",
    "serviceusage.projects.id.apikeys.id",
    "serviceusage.projects.id.services.id",
    "stackdriverlogging.projects.id.sinks.id",
    "stackdriverlogging.projects.id",
    "stackdriverlogging.projects.id.logging_metrics.id",
    "dns.projects.id.policies.id",
    "dns.projects.id.managed_zones.id",
    "computeengine.projects.id.regions.id.subnetworks.id",
    "computeengine.projects.id.zones.id.instances.id",
    "cloudstorage.projects.id.buckets.id",
    "cloudsql.projects.id.instances.id",
    "iam.projects.id.bindings_separation_duties.id",
    "dataproc.projects.id.regions.id.clusters.id",
    "bigquery.projects.id.datasets.id",
    "computeengine.projects.id.networks.id",
    "bigquery.projects.id.datasets.id.tables.id",
    "loadbalancing.projects.id.load_balancers.id",
    "pubsub.projects.id.topics.id.subscriptions.id",
    "pubsub.projects.id.topics.id",
    "functions.projects.id.functions_v1.id",
    "functions.projects.id.functions_v2.id",
    "computeengine.projects.id.firewalls.id",
    "stackdrivermonitoring.projects.id.monitoring_alert_policies.id",
    "computeengine.projects.id.snapshots.id",
    "computeengine.projects.id.zones.id.instances.id.disks.id",
    "cloudmemorystore.projects.id.redis_instances.id",
    "kubernetesengine.projects.id.zones.id.clusters.id",
    "cloudrun.projects.id.services.id",
    "artifactregistry.projects.id.repositories.id",
]
GCP_RESOURCE_TYPE = [
    "GCP.IAM.ServiceAccount",
    "GCP.IAM.Policy",
    "GCP.IAM.User",
    "GCP.KMS.Keys",
    "GCP.SU.ApiKeys",
    "GCP.SU.Services",
    "GCP.CLO.Sink",
    "GCP.CLO.Logging",
    "GCP.CLO.MetricFilter",
    "GCP.DNS.Policy",
    "GCP.DNS.Zone",
    "GCP.GCE.Subnetwork",
    "GCP.GCE.Instance",
    "GCP.STO.Bucket",
    "GCP.SQL.Instance",
    "GCP.IAM.BindingSeparationDuties",
    "GCP.DPR.Cluster",
    "GCP.BQ.Dataset",
    "GCP.GCE.Network",
    "GCP.BQ.Table",
    "GCP.CLB.LoandBalancer",
    "GCP.PUS.Subscription",
    "GCP.PUS.Topic",
    "GCP.GCFv1.Function",
    "GCP.GCFv2.Function",
    "GCP.GCE.Firewall",
    "GCP.CLO.MonitoringAlertPolicy",
    "GCP.GCE.Snapshot",
    "GCP.GCE.Disk",
    "GCP.CMS.RedisInstance",
    "GCP.GKE.Node",
    "GCP.CLR.Service",
    "GCP.GAR.Repository",
]
GCP_REGIONS_KEY = "projects"
# GCP_REGIONS = ["cyberq-cis-certification"]


EKS_RESOURCE_PATH = [
    {
        "display_path": "a_p_i_service.v1-apiregistration-k8s-io.resources.id",
        "resource_type": "AWS.EKS.APIService",
    },
    {"display_path": "eks.id", "resource_type": "AWS.EKS.Cluster"},
    {
        "display_path": "certificate_signing_request.v1-certificates-k8s-io.resources.id",
        "resource_type": "AWS.EKS.CertificateSigningRequest",
    },
    {
        "display_path": "cluster_role.v1-rbac-authorization-k8s-io.resources.id",
        "resource_type": "AWS.EKS.ClusterRole",
    },
    {
        "display_path": "cluster_role_binding.v1-rbac-authorization-k8s-io.resources.id",
        "resource_type": "AWS.EKS.ClusterRoleBinding",
    },
    {
        "display_path": "c_n_i_node.v1alpha1-vpcresources-k8s-aws.resources.id",
        "resource_type": "AWS.EKS.CNINode",
    },
    {
        "display_path": "component_status.v1.resources.id",
        "resource_type": "AWS.EKS.ComponentStatus",
    },
    {
        "display_path": "config_map.v1.resources.id",
        "resource_type": "AWS.EKS.ConfigMap",
    },
    {
        "display_path": "controller_revision.v1-apps.resources.id",
        "resource_type": "AWS.EKS.ControllerRevision",
    },
    {
        "display_path": "c_s_i_driver.v1-storage-k8s-io.resources.id",
        "resource_type": "AWS.EKS.CSIDriver",
    },
    {
        "display_path": "c_s_i_node.v1-storage-k8s-io.resources.id",
        "resource_type": "AWS.EKS.CSINode",
    },
    {
        "display_path": "custom_resource_definition.v1-apiextensions-k8s-io.resources.id",
        "resource_type": "AWS.EKS.CustomResourceDefinition",
    },
    {
        "display_path": "daemon_set.v1-app.resources.id",
        "resource_type": "AWS.EKS.DaemonSet",
    },
    {
        "display_path": "deployment.v1-apps.resources.id",
        "resource_type": "AWS.EKS.Deployment",
    },
    {
        "display_path": "endpoints.v1.resources.id",
        "resource_type": "AWS.EKS.Endpoints",
    },
    {
        "display_path": "endpoint_slice.v1-discovery-k8s-io.resources.id",
        "resource_type": "AWS.EKS.EndpointSlice",
    },
    {
        "display_path": "event.v1-events-k8s-io.resources.id",
        "resource_type": "AWS.EKS.Event",
    },
    {
        "display_path": "flow_schema.v1beta1-flowcontrol-apiserver-k8s-io.resources.id",
        "resource_type": "AWS.EKS.FlowSchema",
    },
    {
        "display_path": "lease.v1-coordination-k8s-io.resources.id",
        "resource_type": "AWS.EKS.Lease",
    },
    {
        "display_path": "mutating_webhook_configuration.v1-admissionregistration-k8s-io.resources.id",
        "resource_type": "AWS.EKS.MutatingWebhookConfiguration",
    },
    {
        "display_path": "namespace.v1.resources.id",
        "resource_type": "AWS.EKS.Namespace",
    },
    {
        "display_path": "network_policy.v1-networking-k8s-io.resources.id",
        "resource_type": "AWS.EKS.NetworkPolicy",
    },
    {
        "display_path": "node.v1.resources.id",
        "resource_type": "AWS.EKS.Node",
    },
    {
        "display_path": "pod.v1.resources.id",
        "resource_type": "AWS.EKS.Pod",
    },
    {
        "display_path": "priority_class.v1-scheduling-k8s-io.resources.id",
        "resource_type": "AWS.EKS.PriorityClass",
    },
    {
        "display_path": "priority_level_configuration.v1beta1-flowcontrol-apiserver-k8s-io.resources.id",
        "resource_type": "AWS.EKS.PriorityLevelConfiguration",
    },
    {
        "display_path": "pod_security_policy.v1beta1-policy.resources.id",
        "resource_type": "AWS.EKS.PSP",
    },
    {
        "display_path": "rbac.cluster_role_v1-rbac-authorization-k8s-io.resources.id",
        "resource_type": "AWS.EKS.RBACClusterRole",
    },
    {
        "display_path": "rbac.cluster_role_binding_v1-rbac-authorization-k8s-io.resources.id",
        "resource_type": "AWS.EKS.RBACClusterRoleBinding",
    },
    {
        "display_path": "replica_set.v1-apps.resources.id",
        "resource_type": "AWS.EKS.ReplicaSet",
    },
    {
        "display_path": "role.v1-rbac-authorization-k8s-io.resources.id",
        "resource_type": "AWS.EKS.Role",
    },
    {
        "display_path": "role_binding.v1-rbac-authorization-k8s-io.resources.id",
        "resource_type": "AWS.EKS.RoleBinding",
    },
    {
        "display_path": "secret.v1.resources.id",
        "resource_type": "AWS.EKS.Secret",
    },
    {
        "display_path": "service.v1.resources.id",
        "resource_type": "AWS.EKS.Service",
    },
    {
        "display_path": "service_account.v1.resources.id",
        "resource_type": "AWS.EKS.ServiceAccount",
    },
    {
        "display_path": "storage_class.v1-storage-k8s-io.resources.id",
        "resource_type": "AWS.EKS.StorageClass",
    },
    {
        "display_path": "validating_webhook_configuration.v1-admissionregistration-k8s-io.resources.id",
        "resource_type": "AWS.EKS.ValidatingWebhookConfiguration",
    },
    {
        "display_path": "version.details.id",
        "resource_type": "AWS.EKS.Version",
    },
]
EKS_DISPLAY_PATH = [
    "a_p_i_service.v1-apiregistration-k8s-io.resources.id",
    "eks.id",
    "certificate_signing_request.v1-certificates-k8s-io.resources.id",
    "cluster_role.v1-rbac-authorization-k8s-io.resources.id",
    "cluster_role_binding.v1-rbac-authorization-k8s-io.resources.id",
    "c_n_i_node.v1alpha1-vpcresources-k8s-aws.resources.id",
    "component_status.v1.resources.id",
    "config_map.v1.resources.id",
    "controller_revision.v1-apps.resources.id",
    "c_s_i_driver.v1-storage-k8s-io.resources.id",
    "c_s_i_node.v1-storage-k8s-io.resources.id",
    "custom_resource_definition.v1-apiextensions-k8s-io.resources.id",
    "daemon_set.v1-app.resources.id",
    "deployment.v1-apps.resources.id",
    "endpoints.v1.resources.id",
    "endpoint_slice.v1-discovery-k8s-io.resources.id",
    "event.v1-events-k8s-io.resources.id",
    "flow_schema.v1beta1-flowcontrol-apiserver-k8s-io.resources.id",
    "lease.v1-coordination-k8s-io.resources.id",
    "mutating_webhook_configuration.v1-admissionregistration-k8s-io.resources.id",
    "namespace.v1.resources.id",
    "network_policy.v1-networking-k8s-io.resources.id",
    "node.v1.resources.id",
    "pod.v1.resources.id",
    "priority_class.v1-scheduling-k8s-io.resources.id",
    "priority_level_configuration.v1beta1-flowcontrol-apiserver-k8s-io.resources.id",
    "pod_security_policy.v1beta1-policy.resources.id",
    "rbac.cluster_role_v1-rbac-authorization-k8s-io.resources.id",
    "rbac.cluster_role_binding_v1-rbac-authorization-k8s-io.resources.id",
    "replica_set.v1-apps.resources.id",
    "role.v1-rbac-authorization-k8s-io.resources.id",
    "role_binding.v1-rbac-authorization-k8s-io.resources.id",
    "secret.v1.resources.id",
    "service.v1.resources.id",
    "service_account.v1.resources.id",
    "storage_class.v1-storage-k8s-io.resources.id",
    "validating_webhook_configuration.v1-admissionregistration-k8s-io.resources.id",
    "version.details.id",
]
EKS_RESOURCE_TYPE = [
    "AWS.EKS.APIService",
    "AWS.EKS.Cluster",
    "AWS.EKS.CertificateSigningRequest",
    "AWS.EKS.ClusterRole",
    "AWS.EKS.ClusterRoleBinding",
    "AWS.EKS.CNINode",
    "AWS.EKS.ComponentStatus",
    "AWS.EKS.ConfigMap",
    "AWS.EKS.ControllerRevision",
    "AWS.EKS.CSIDriver",
    "AWS.EKS.CSINode",
    "AWS.EKS.CustomResourceDefinition",
    "AWS.EKS.DaemonSet",
    "AWS.EKS.Deployment",
    "AWS.EKS.Endpoints",
    "AWS.EKS.EndpointSlice",
    "AWS.EKS.Event",
    "AWS.EKS.FlowSchema",
    "AWS.EKS.Lease",
    "AWS.EKS.MutatingWebhookConfiguration",
    "AWS.EKS.Namespace",
    "AWS.EKS.NetworkPolicy",
    "AWS.EKS.Node",
    "AWS.EKS.Pod",
    "AWS.EKS.PriorityClass",
    "AWS.EKS.PriorityLevelConfiguration",
    "AWS.EKS.PSP",
    "AWS.EKS.RBACClusterRole",
    "AWS.EKS.RBACClusterRoleBinding",
    "AWS.EKS.ReplicaSet",
    "AWS.EKS.Role",
    "AWS.EKS.RoleBinding",
    "AWS.EKS.Secret",
    "AWS.EKS.Service",
    "AWS.EKS.ServiceAccount",
    "AWS.EKS.StorageClass",
    "AWS.EKS.ValidatingWebhookConfiguration",
    "AWS.EKS.Version",
    "AWS.EKS.Workload",
]
GCP_RTM_SERVICES_LIST = [
    "compute",
    "cloudfunctions",
    "iam",
    "cloudkms",
    "cloudsql",
    "storage",
    "apikeys",
    "serviceusage",
    "bigquery",
]
GCP_RTM_SERVICES = [
    {
        "rtm_service": "compute",
        "rule_db_service": "Compute Engine",
        "scanner_service": "gce",
    },
    {
        "rtm_service": "cloudfunctions",
        "rule_db_service": "Functions",
        "scanner_service": "functions",
    },
    {
        "rtm_service": "iam",
        "rule_db_service": "IAM",
        "scanner_service": "iam",
    },
    {
        "rtm_service": "cloudkms",
        "rule_db_service": "KMS",
        "scanner_service": "kms",
    },
    {
        "rtm_service": "cloudsql",
        "rule_db_service": "SQL",
        "scanner_service": "cloudsql",
    },
    {
        "rtm_service": "storage",
        "rule_db_service": "Storage",
        "scanner_service": "cloudstorage",
    },
    {
        "rtm_service": "apikeys",
        "rule_db_service": "No Service",
        "scanner_service": "serviceusage",
    },
    {
        "rtm_service": "serviceusage",
        "rule_db_service": "Service Usage (SU)",
        "scanner_service": "serviceusage",
    },
    {
        "rtm_service": "bigquery",
        "rule_db_service": "Bigquery",
        "scanner_service": "bigquery",
    },
]
