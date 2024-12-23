provider "aws" {
  region = var.region
}

variable "region" {
  type    = string
  default = "ap-southeast-1"
}

variable "cloudtrail" {
  type    = string
  default = "codepipeline-source-trail"
}

variable "cloudwatch" {
  type    = string
  default = "codepipeline-source-trail"
}

variable "s3bucket" {
  type    = string
  default = "codepipeline-cloudtrail-placeholder-bucket-ap-southeast-1"
}

variable "iam_role" {
  type    = string
  default = "codepipeline-source-trail"
}

# SNS Topic for CIS Benchmark Alarms
resource "aws_sns_topic" "cis_benchmark_alarms" {
  name = "cis-benchmark-alarms"
}

resource "aws_sns_topic_subscription" "email_subscription" {
  topic_arn = aws_sns_topic.cis_benchmark_alarms.arn
  protocol  = "email"
  endpoint  = "your-email@example.com" # Replace with your email
}

# Data sources to check for existing resources
data "aws_cloudtrail" "existing_cloudtrail" {
  name = var.cloudtrail
}

data "aws_cloudwatch_log_group" "existing_log_group" {
  name = var.cloudwatch
}

data "aws_s3_bucket" "existing_s3_bucket" {
  bucket = var.s3bucket
}

data "aws_iam_role" "existing_iam_role" {
  name = var.iam_role
}

# CloudTrail
resource "aws_cloudtrail" "cis_benchmark_trail" {
  count = length(data.aws_cloudtrail.existing_cloudtrail.id) == 0 ? 1 : 0
  
  name                          = var.cloudtrail
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  cloud_watch_logs_group_arn    = aws_cloudwatch_log_group.cis_benchmark_log_group.arn
  cloud_watch_logs_role_arn     = aws_iam_role.cis_benchmark_role.arn
  s3_bucket_name                = data.aws_s3_bucket.existing_s3_bucket.id
  include_global_service_events = true
}

# IAM Role for CloudTrail to write logs to CloudWatch
resource "aws_iam_role" "cis_benchmark_role" {
  count = length(data.aws_iam_role.existing_iam_role.id) == 0 ? 1 : 0
  
  name = var.iam_role

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action    = "sts:AssumeRole",
        Effect    = "Allow",
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "cis_benchmark_policy" {
  name = "cis-benchmark-policy"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        Effect   = "Allow",
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_policy" {
  role       = aws_iam_role.cis_benchmark_role.name
  policy_arn = aws_iam_policy.cis_benchmark_policy.arn
}

resource "aws_cloudwatch_log_group" "cis_benchmark_log_group" {
  count = length(data.aws_cloudwatch_log_group.existing_log_group.id) == 0 ? 1 : 0
  name  = var.cloudwatch
}

# CloudWatch Metric Filters and Alarms
locals {
  cis_benchmark_metrics = {
    # [AWS CIS] 3.1 - Ensure a log metric filter and alarm exist for unauthorized API calls
    UnauthorizedAPICalls = {
      pattern   = "{($.errorCode=\"*UnauthorizedOperation\") || ($.errorCode=\"AccessDenied*\")}"
      namespace = "CISBenchmark"
    }

    # [AWS CIS] 3.3 - Ensure a log metric filter and alarm exist for usage of 'root' account
    RootAccountUsage = {
      pattern   = "{($.userIdentity.type=\"Root\") && $.userIdentity.invokedBy NOT EXISTS && $.eventType !=\"AwsServiceEvent\"}"
      namespace = "CISBenchmark"
    }

    # [AWS CIS] 3.4 - Ensure a log metric filter and alarm exist for IAM policy changes
    IamPolicyChange = {
      pattern   = "{($.eventSource=\"iam.amazonaws.com\") && (($.eventName=\"DeleteGroupPolicy\") || ($.eventName=\"DeleteRolePolicy\") || ($.eventName=\"DeleteUserPolicy\") || ($.eventName=\"PutGroupPolicy\") || ($.eventName=\"PutRolePolicy\") || ($.eventName=\"PutUserPolicy\") || ($.eventName=\"CreatePolicy\") || ($.eventName=\"DeletePolicy\") || ($.eventName=\"CreatePolicyVersion\") || ($.eventName=\"DeletePolicyVersion\") || ($.eventName=\"AttachRolePolicy\") || ($.eventName=\"DetachRolePolicy\") || ($.eventName=\"AttachUserPolicy\") || ($.eventName=\"DetachUserPolicy\") || ($.eventName=\"AttachGroupPolicy\") || ($.eventName=\"DetachGroupPolicy\"))}"
      namespace = "CISBenchmark"
    }

    # [AWS CIS] 3.5 - Ensure a log metric filter and alarm exist for CloudTrail configuration changes
    CloudTrailConfigChange = {
      pattern   = "{($.eventName=\"CreateTrail\") || ($.eventName=\"UpdateTrail\") || ($.eventName=\"DeleteTrail\") || ($.eventName=\"StartLogging\") || ($.eventName=\"StopLogging\")}"
      namespace = "CISBenchmark"
    }

    # [AWS CIS] 3.6 - Ensure a log metric filter and alarm exist for AWS Management Console authentication failures
    SignInFailures = {
      pattern   = "{($.eventName=\"ConsoleLogin\") && ($.errorMessage=\"Failed authentication\")}"
      namespace = "CISBenchmark"
    }

    # [AWS CIS] 3.7 - Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer managed keys
    CMKDisabledOrScheduledDeleted = {
      pattern   = "{($.eventSource=\"kms.amazonaws.com\") && (($.eventName=\"DisableKey\") || ($.eventName=\"ScheduleKeyDeletion\"))}"
      namespace = "CISBenchmark"
    }

    # [AWS CIS] 3.8 - Ensure a log metric filter and alarm exist for S3 bucket policy changes
    S3BucketPolicyChange = {
      pattern   = "{($.eventSource=\"s3.amazonaws.com\") && (($.eventName=\"PutBucketAcl\") || ($.eventName=\"PutBucketPolicy\") || ($.eventName=\"PutBucketCors\") || ($.eventName=\"PutBucketLifecycle\") || ($.eventName=\"PutBucketReplication\") || ($.eventName=\"DeleteBucketPolicy\") || ($.eventName=\"DeleteBucketCors\") || ($.eventName=\"DeleteBucketLifecycle\") || ($.eventName=\"DeleteBucketReplication\"))}"
      namespace = "CISBenchmark"
    }

    # [AWS CIS] 3.9 - Ensure a log metric filter and alarm exist for AWS Config configuration changes
    AwsConfigConfigurationChange = {
      pattern   = "{($.eventSource=\"config.amazonaws.com\") && (($.eventName=\"StopConfigurationRecorder\") || ($.eventName=\"DeleteDeliveryChannel\") || ($.eventName=\"PutDeliveryChannel\") || ($.eventName=\"PutConfigurationRecorder\"))}"
      namespace = "CISBenchmark"
    }

    # [AWS CIS] 3.10 - Ensure a log metric filter and alarm exist for security group changes
    SecurityGroupChanges = {
      pattern   = "{($.eventName=\"AuthorizeSecurityGroupIngress\") || ($.eventName=\"AuthorizeSecurityGroupEgress\") || ($.eventName=\"RevokeSecurityGroupIngress\") || ($.eventName=\"RevokeSecurityGroupEgress\") || ($.eventName=\"CreateSecurityGroup\") || ($.eventName=\"DeleteSecurityGroup\")}"
      namespace = "CISBenchmark"
    }

    # [AWS CIS] 3.11 - Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)
    NACLChanges = {
      pattern   = "{($.eventName=\"CreateNetworkAcl\") || ($.eventName=\"CreateNetworkAclEntry\") || ($.eventName=\"DeleteNetworkAcl\") || ($.eventName=\"DeleteNetworkAclEntry\") || ($.eventName=\"ReplaceNetworkAclEntry\") || ($.eventName=\"ReplaceNetworkAclAssociation\")}"
      namespace = "CISBenchmark"
    }

    # [AWS CIS] 3.12 - Ensure a log metric filter and alarm exist for changes to network gateways (Automated)
    NetworkGatewayChange = {
      pattern   = "{($.eventName=\"CreateCustomerGateway\") || ($.eventName=\"DeleteCustomerGateway\") || ($.eventName=\"AttachInternetGateway\") || ($.eventName=\"CreateInternetGateway\") || ($.eventName=\"DeleteInternetGateway\") || ($.eventName=\"DetachInternetGateway\")}"
      namespace = "CISBenchmark"
    }

    # [AWS CIS] 3.13 Ensure a log metric filter and alarm exist for route table changes
    RouteTableChange = {
      pattern   = "{($.eventSource=\"ec2.amazonaws.com\") && (($.eventName=\"CreateRoute\") || ($.eventName=\"CreateRouteTable\") || ($.eventName=\"ReplaceRoute\") || ($.eventName=\"ReplaceRouteTableAssociation\") || ($.eventName=\"DeleteRouteTable\") || ($.eventName=\"DeleteRoute\") || ($.eventName=\"DisassociateRouteTable\"))}"
      namespace = "CISBenchmark"
    }

    # [AWS CIS] 3.14 Ensure a log metric filter and alarm exist for VPC changes
    VpcChange = {
      pattern   = "{($.eventName=\"CreateVpc\") || ($.eventName=\"DeleteVpc\") || ($.eventName=\"ModifyVpcAttribute\") || ($.eventName=\"AcceptVpcPeeringConnection\") || ($.eventName=\"CreateVpcPeeringConnection\") || ($.eventName=\"DeleteVpcPeeringConnection\") || ($.eventName=\"RejectVpcPeeringConnection\") || ($.eventName=\"AttachClassicLinkVpc\") || ($.eventName=\"DetachClassicLinkVpc\") || ($.eventName=\"DisableVpcClassicLink\") || ($.eventName=\"EnableVpcClassicLink\")}"
      namespace = "CISBenchmark"
    }
  }
}


# Metric Filters and Alarms Creation
resource "aws_cloudwatch_metric_filter" "cis_benchmark_filters" {
  for_each          = local.metric_filters
  log_group_name    = aws_cloudwatch_log_group.cis_benchmark_log_group.name
  filter_pattern    = each.value.pattern
  metric_transformation {
    namespace = each.value.namespace
    name      = each.value.metric
    value     = "1"
  }
}

resource "aws_cloudwatch_alarm" "cis_benchmark_alarms" {
  for_each                = local.metric_filters
  alarm_name              = "${each.key}-alarm"
  comparison_operator     = "GreaterThanOrEqualToThreshold"
  evaluation_periods      = 1
  metric_name             = each.value.metric
  namespace               = each.value.namespace
  period                  = 300
  statistic               = "Sum"
  threshold               = 1
  alarm_actions           = [aws_sns_topic.cis_benchmark_alarms.arn]
  insufficient_data_actions = []
}
