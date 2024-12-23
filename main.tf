provider "aws" {
  region = var.region # Change to your preferred region
}

variable region {
  type    = string
  default ="ap-southeast-1"
}

variable cloudtrail {
  type    = string
  default ="ap-southeast-1"
}

variable cloudwatch {
  type    = string
  default = "/aws/cloudtrail/cis-benchmark"
}

variable s3bucket {
  type    = string
  default ="ap-southeast-1"
}

variable iam_role {
  type    = string
  default ="ap-southeast-1"
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
  name = "cis-benchmark-trail"
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
  count = length(data.aws_cloudtrail.existing_cloudtrail) == 0 ? 1 : 0
  
  name                          = "cis-benchmark-trail"
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  cloud_watch_logs_group_arn    = aws_cloudwatch_log_group.cis_benchmark_log_group.arn
  cloud_watch_logs_role_arn     = aws_iam_role.cis_benchmark_role.arn
  s3_bucket_name                = aws_s3_bucket.cis_benchmark_bucket.id
  include_global_service_events = true
}

resource "aws_s3_bucket" "cis_benchmark_bucket" {
  count  = length(data.aws_s3_bucket.existing_s3_bucket) == 0 ? 1 : 0
  bucket = "cis-benchmark-trail-bucket-${random_id.bucket_suffix.hex}"

  versioning {
    enabled = true
  }

  lifecycle_rule {
    enabled = true

    transition {
      days          = 30
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

# IAM Role for CloudTrail to write logs to CloudWatch
resource "aws_iam_role" "cis_benchmark_role" {
  count = length(data.aws_iam_role.existing_iam_role) == 0 ? 1 : 0
  
  name = "cis-benchmark-role"

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
  count = length(data.aws_cloudwatch_log_group.existing_log_group) == 0 ? 1 : 0
  name  = "/aws/cloudtrail/cis-benchmark"
}

# CloudWatch Metric Filters and Alarms
locals {
  metric_filters = {
    "UnauthorizedAPICalls" = {
      pattern   = "{($.errorCode=\"*UnauthorizedOperation\") || ($.errorCode=\"AccessDenied*\")}"
      namespace = "CISBenchmark"
      metric    = "UnauthorizedAPICalls"
    },
    "RootAccountUsage" = {
      pattern   = "{($.userIdentity.type=\"Root\") && ($.userIdentity.invokedBy NOT EXISTS) && ($.eventType!=\"AwsServiceEvent\")}"
      namespace = "CISBenchmark"
      metric    = "RootAccountUsage"
    },
    "IamPolicyChange" = {
      pattern   = "{($.eventSource=\"iam.amazonaws.com\") && (($.eventName=\"PutUserPolicy\") || ($.eventName=\"DeleteUserPolicy\") || ($.eventName=\"AttachUserPolicy\"))}"
      namespace = "CISBenchmark"
      metric    = "IamPolicyChange"
    }
    # Add additional metrics as needed
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
