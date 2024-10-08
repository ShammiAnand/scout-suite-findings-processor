from typing import Literal

ALLOWED_SERVICES = [
    "acm",
    "awslambda",
    "autoscaling",
    "athena",
    "apigateway",
    "apigatewayv2",
    "appsync",
    "codebuild",
    "docdb",
    "dms",
    "backup",
    "cloudformation",
    "ssm",
    "cloudtrail",
    "cloudwatch",
    "cloudfront",
    "cognito",
    "directconnect",
    "dynamodb",
    "ec2",
    "efs",
    "elasticache",
    "elb",
    "elbv2",
    "emr",
    "eks",
    "glue",
    "iam",
    "inspector2",
    "kinesis",
    "kms",
    "neptune",
    "rds",
    "redshift",
    "route53",
    "s3",
    "sagemaker",
    "ses",
    "stepfunctions",
    "sns",
    "organization",
    "ecr",
    "elasticbeanstalk",
    "ecs",
    "sqs",
    "secretsmanager",
    "waf",
    "wafv2",
    "networkfirewall",
    "opensearch",
    "pca",
    "vpc",
    "guardduty",
]

SERVICES = Literal[
    "acm",
    "awslambda",
    "autoscaling",
    "athena",
    "apigateway",
    "apigatewayv2",
    "appsync",
    "codebuild",
    "docdb",
    "dms",
    "backup",
    "cloudformation",
    "ssm",
    "cloudtrail",
    "cloudwatch",
    "cloudfront",
    "cognito",
    "directconnect",
    "dynamodb",
    "ec2",
    "efs",
    "elasticache",
    "elb",
    "elbv2",
    "emr",
    "eks",
    "glue",
    "iam",
    "inspector2",
    "kinesis",
    "kms",
    "neptune",
    "rds",
    "redshift",
    "route53",
    "s3",
    "sagemaker",
    "ses",
    "stepfunctions",
    "sns",
    "organization",
    "ecr",
    "elasticbeanstalk",
    "ecs",
    "sqs",
    "secretsmanager",
    "waf",
    "wafv2",
    "networkfirewall",
    "opensearch",
    "pca",
    "vpc",
    "guardduty",
]

COMPLIANCE_CONTROLS = Literal[
    "awaf",
    "cis",
    "cis_eks",
    "nist_rev4",
    "nist_rev5",
    "iso",
    "ccmv3",
    "ccm_v4.0.5",
    "pci_dss_v3.2.1",
    "gdpr",
    "soc2",
    "popi_act",
    "hipaa",
    "iso_2022",
    "fedramp",
    "cmmc",
    "fisma",
    "nydfs",
    "aws_fsbp",
    "sama_csf",
    "pci_dss_v4.0",
    "cbb",
]
