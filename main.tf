provider "aws" {
  region = var.region
}

variable "region" {
  type    = string
  default = "ap-southeast-1"
}

variable "cloudwatch_log_group" {
  type    = string
  default = "codepipeline-source-trail"  # Existing log group name
}

variable "sns_email" {
  type    = string
  default = "your-email@example.com"  # Replace with your email address
}

# SNS Topic for CIS Benchmark Alarms
resource "aws_sns_topic" "cis_benchmark_alarms" {
  name = "cis-benchmark-alarms"
}

resource "aws_sns_topic_subscription" "email_subscription" {
  topic_arn = aws_sns_topic.cis_benchmark_alarms.arn
  protocol  = "email"
  endpoint  = var.sns_email
}

# Data source to reference existing CloudWatch Log Group
data "aws_cloudwatch_log_group" "existing_log_group" {
  name = var.cloudwatch_log_group
}

# Metric Filters and Alarms Creation
locals {
  # Define the metric filters and their patterns
  metric_filters = {
    UnauthorizedAPICalls = {
      pattern   = "{($.errorCode=\"*UnauthorizedOperation\") || ($.errorCode=\"AccessDenied*\")}"
      namespace = "CISBenchmark"
      metric    = "UnauthorizedAPICallsMetric"
    }

    RootAccountUsage = {
      pattern   = "{($.userIdentity.type=\"Root\") && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\"}"
      namespace = "CISBenchmark"
      metric    = "RootAccountUsageMetric"
    }

    IamPolicyChange = {
      pattern   = "{($.eventSource=\"iam.amazonaws.com\") && (($.eventName=\"DeleteGroupPolicy\") || ($.eventName=\"DeleteRolePolicy\") || ($.eventName=\"DeleteUserPolicy\") || ($.eventName=\"PutGroupPolicy\") || ($.eventName=\"PutRolePolicy\") || ($.eventName=\"PutUserPolicy\") || ($.eventName=\"CreatePolicy\") || ($.eventName=\"DeletePolicy\") || ($.eventName=\"CreatePolicyVersion\") || ($.eventName=\"DeletePolicyVersion\") || ($.eventName=\"AttachRolePolicy\") || ($.eventName=\"DetachRolePolicy\") || ($.eventName=\"AttachUserPolicy\") || ($.eventName=\"DetachUserPolicy\") || ($.eventName=\"AttachGroupPolicy\") || ($.eventName=\"DetachGroupPolicy\"))}"
      namespace = "CISBenchmark"
      metric    = "IamPolicyChangeMetric"
    }

    CloudTrailConfigChange = {
      pattern   = "{($.eventName=\"CreateTrail\") || ($.eventName=\"UpdateTrail\") || ($.eventName=\"DeleteTrail\") || ($.eventName=\"StartLogging\") || ($.eventName=\"StopLogging\")}"
      namespace = "CISBenchmark"
      metric    = "CloudTrailConfigChangeMetric"
    }

    SignInFailures = {
      pattern   = "{($.eventName=\"ConsoleLogin\") && ($.errorMessage=\"Failed authentication\")}"
      namespace = "CISBenchmark"
      metric    = "SignInFailuresMetric"
    }

    CMKDisabledOrScheduledDeleted = {
      pattern   = "{($.eventSource=\"kms.amazonaws.com\") && (($.eventName=\"DisableKey\") || ($.eventName=\"ScheduleKeyDeletion\"))}"
      namespace = "CISBenchmark"
      metric    = "CMKDisabledOrScheduledDeletedMetric"
    }

    S3BucketPolicyChange = {
      pattern   = "{($.eventSource=\"s3.amazonaws.com\") && (($.eventName=\"PutBucketAcl\") || ($.eventName=\"PutBucketPolicy\") || ($.eventName=\"PutBucketCors\") || ($.eventName=\"PutBucketLifecycle\") || ($.eventName=\"PutBucketReplication\") || ($.eventName=\"DeleteBucketPolicy\") || ($.eventName=\"DeleteBucketCors\") || ($.eventName=\"DeleteBucketLifecycle\") || ($.eventName=\"DeleteBucketReplication\"))}"
      namespace = "CISBenchmark"
      metric    = "S3BucketPolicyChangeMetric"
    }

    SecurityGroupChanges = {
      pattern   = "{($.eventName=\"AuthorizeSecurityGroupIngress\") || ($.eventName=\"AuthorizeSecurityGroupEgress\") || ($.eventName=\"RevokeSecurityGroupIngress\") || ($.eventName=\"RevokeSecurityGroupEgress\") || ($.eventName=\"CreateSecurityGroup\") || ($.eventName=\"DeleteSecurityGroup\")}"
      namespace = "CISBenchmark"
      metric    = "SecurityGroupChangesMetric"
    }
  }
}

# Create Metric Filters for CloudWatch Logs
resource "aws_cloudwatch_metric_filter" "cis_benchmark_filters" {
  for_each          = local.metric_filters
  log_group_name    = data.aws_cloudwatch_log_group.existing_log_group.name
  filter_pattern    = each.value.pattern

  metric_transformation {
    namespace = each.value.namespace
    name      = each.value.metric
    value     = "1"
  }
}

# Create CloudWatch Alarms for the metric filters
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
