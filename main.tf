# AWS Security Monitoring Configuration
# Implements CIS Benchmark alerts for critical security events

provider "aws" {
  region = var.region
}

# Variables
variable "region" {
  type        = string
  default     = "ap-southeast-1"
  description = "AWS region for deploying resources"
}

variable "metric_period" {
  description = "The period in seconds over which the metrics should be evaluated"
  type        = number
  default     = 300
}

variable env {
  type        = string
  default     = "stag"
}

variable cloudscape_id {
  type        = string
  default     = "AWS-1169"
}

variable "cloudwatch_log_group" {
  type        = string
  default     = "codepipeline-source-trail"
  description = "Existing CloudWatch Log Group name for CloudTrail logs"
}

variable "sns_email" {
  type        = string
  description = "Email address for receiving security alerts"
  validation {
    condition     = can(regex("^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$", var.sns_email))
    error_message = "Must be a valid email address."
  }
}

# SNS Topic for Security Alerts
resource "aws_sns_topic" "security_alerts" {
  name              = "security-monitoring-alerts"
  kms_master_key_id = aws_kms_key.sns_encryption.id  # Enable encryption
  
  tags = {
    Environment = "${var.env}"
    Purpose     = "${var.cloudscape_id}"
  }
}

# KMS Key for SNS Topic Encryption
resource "aws_kms_key" "sns_encryption" {
  description             = "KMS key for SNS topic encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }
        Action   = "kms:*"
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

# Get current AWS account ID
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_subscription" "security_alerts_email" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.sns_email
}

# Metric Filters Configuration
locals {
  metric_filters = {
    # [AWS CIS] 3.1 - Unauthorized API Calls
    UnauthorizedAPICalls = {
      pattern      = "{($.errorCode=\"*UnauthorizedOperation\") || ($.errorCode=\"AccessDenied*\")}"
      namespace    = "CISBenchmark"
      metric_name  = "UnauthorizedAPICalls"
      description  = "Unauthorized API calls"
      threshold    = 1
      period      = var.metric_period
    }

    # [AWS CIS] 3.3 - Root Account Usage
    RootAccountUsage = {
      pattern      = "{$.userIdentity.type=\"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !=\"AwsServiceEvent\"}"
      namespace    = "CISBenchmark"
      metric_name  = "RootAccountUsage"
      description  = "Usage of root account"
      threshold    = 1
      period      = var.metric_period
    }

    # [AWS CIS] 3.4 - IAM Policy Changes
    IamPolicyChange = {
      pattern      = "{($.eventSource=iam.amazonaws.com) && (($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy) || ($.eventName=AttachGroupPolicy) || ($.eventName=DetachGroupPolicy))}"
      namespace    = "CISBenchmark"
      metric_name  = "IamPolicyChange"
      description  = "Changes to IAM policies"
      threshold    = 1
      period      = var.metric_period
    }

    # [AWS CIS] 3.5 - CloudTrail Configuration Changes
    CloudTrailConfigChange = {
      pattern      = "{($.eventName=CreateTrail) || ($.eventName=UpdateTrail) || ($.eventName=DeleteTrail) || ($.eventName=StartLogging) || ($.eventName=StopLogging)}"
      namespace    = "CISBenchmark"
      metric_name  = "CloudTrailConfigChange"
      description  = "Changes to CloudTrail configuration"
      threshold    = 1
      period      = var.metric_period
    }

    # [AWS CIS] 3.6 - Console Authentication Failures
    SignInFailures = {
      pattern      = "{($.eventName=ConsoleLogin) && ($.errorMessage=\"Failed authentication\")}"
      namespace    = "CISBenchmark"
      metric_name  = "SignInFailures"
      description  = "AWS Console authentication failures"
      threshold    = 1
      period      = var.metric_period
    }

    # [AWS CIS] 3.7 - Disabled or Scheduled Deletion of CMKs
    CMKDisabledOrScheduledDeleted = {
      pattern      = "{($.eventSource=kms.amazonaws.com) && (($.eventName=DisableKey) || ($.eventName=ScheduleKeyDeletion))}"
      namespace    = "CISBenchmark"
      metric_name  = "CMKDisabledOrScheduledDeleted"
      description  = "Customer managed keys disabled or scheduled for deletion"
      threshold    = 1
      period      = var.metric_period
    }

    # [AWS CIS] 3.8 - S3 Bucket Policy Changes
    S3BucketPolicyChange = {
      pattern      = "{($.eventSource=s3.amazonaws.com) && (($.eventName=PutBucketAcl) || ($.eventName=PutBucketPolicy) || ($.eventName=PutBucketCors) || ($.eventName=PutBucketLifecycle) || ($.eventName=PutBucketReplication) || ($.eventName=DeleteBucketPolicy) || ($.eventName=DeleteBucketCors) || ($.eventName=DeleteBucketLifecycle) || ($.eventName=DeleteBucketReplication))}"
      namespace    = "CISBenchmark"
      metric_name  = "S3BucketPolicyChange"
      description  = "Changes to S3 bucket policies"
      threshold    = 1
      period      = var.metric_period
    }

    # [AWS CIS] 3.9 - AWS Config Configuration Changes
    AwsConfigConfigurationChange = {
      pattern      = "{($.eventSource=config.amazonaws.com) && (($.eventName=StopConfigurationRecorder) || ($.eventName=DeleteDeliveryChannel) || ($.eventName=PutDeliveryChannel) || ($.eventName=PutConfigurationRecorder))}"
      namespace    = "CISBenchmark"
      metric_name  = "AwsConfigConfigurationChange"
      description  = "Changes to AWS Config configuration"
      threshold    = 1
      period      = var.metric_period
    }

    # [AWS CIS] 3.10 - Security Group Changes
    SecurityGroupChanges = {
      pattern      = "{($.eventName=AuthorizeSecurityGroupIngress) || ($.eventName=AuthorizeSecurityGroupEgress) || ($.eventName=RevokeSecurityGroupIngress) || ($.eventName=RevokeSecurityGroupEgress) || ($.eventName=CreateSecurityGroup) || ($.eventName=DeleteSecurityGroup)}"
      namespace    = "CISBenchmark"
      metric_name  = "SecurityGroupChanges"
      description  = "Changes to security groups"
      threshold    = 1
      period      = var.metric_period
    }

    # [AWS CIS] 3.11 - NACL Changes
    NACLChanges = {
      pattern      = "{($.eventName=CreateNetworkAcl) || ($.eventName=CreateNetworkAclEntry) || ($.eventName=DeleteNetworkAcl) || ($.eventName=DeleteNetworkAclEntry) || ($.eventName=ReplaceNetworkAclEntry) || ($.eventName=ReplaceNetworkAclAssociation)}"
      namespace    = "CISBenchmark"
      metric_name  = "NACLChanges"
      description  = "Changes to Network Access Control Lists"
      threshold    = 1
      period      = var.metric_period
    }

    # [AWS CIS] 3.12 - Network Gateway Changes
    NetworkGatewayChange = {
      pattern      = "{($.eventName=CreateCustomerGateway) || ($.eventName=DeleteCustomerGateway) || ($.eventName=AttachInternetGateway) || ($.eventName=CreateInternetGateway) || ($.eventName=DeleteInternetGateway) || ($.eventName=DetachInternetGateway)}"
      namespace    = "CISBenchmark"
      metric_name  = "NetworkGatewayChange"
      description  = "Changes to network gateways"
      threshold    = 1
      period      = var.metric_period
    }

    # [AWS CIS] 3.13 - Route Table Changes
    RouteTableChange = {
      pattern      = "{($.eventSource=ec2.amazonaws.com) && (($.eventName=CreateRoute) || ($.eventName=CreateRouteTable) || ($.eventName=ReplaceRoute) || ($.eventName=ReplaceRouteTableAssociation) || ($.eventName=DeleteRouteTable) || ($.eventName=DeleteRoute) || ($.eventName=DisassociateRouteTable))}"
      namespace    = "CISBenchmark"
      metric_name  = "RouteTableChange"
      description  = "Changes to route tables"
      threshold    = 1
      period      = var.metric_period
    }

    # [AWS CIS] 3.14 - VPC Changes
    VpcChange = {
      pattern      = "{($.eventName=CreateVpc) || ($.eventName=DeleteVpc) || ($.eventName=ModifyVpcAttribute) || ($.eventName=AcceptVpcPeeringConnection) || ($.eventName=CreateVpcPeeringConnection) || ($.eventName=DeleteVpcPeeringConnection) || ($.eventName=RejectVpcPeeringConnection) || ($.eventName=AttachClassicLinkVpc) || ($.eventName=DetachClassicLinkVpc) || ($.eventName=DisableVpcClassicLink) || ($.eventName=EnableVpcClassicLink)}"
      namespace    = "CISBenchmark"
      metric_name  = "VpcChange"
      description  = "Changes to VPC configuration"
      threshold    = 1
      period      = var.metric_period
    }
  }
}

data "aws_cloudwatch_log_group" "cloudtrail_logs" {
  name = var.cloudwatch_log_group
}

# Create Log Metric Filters
resource "aws_cloudwatch_log_metric_filter" "security_filters" {
  for_each       = local.metric_filters
  name           = "${each.key}Filter"
  pattern        = each.value.pattern
  log_group_name = data.aws_cloudwatch_log_group.cloudtrail_logs.name

  metric_transformation {
    name      = each.value.metric_name
    namespace = each.value.namespace
    value     = "1"
    unit      = "Count"
  }
}

# Create CloudWatch Metric Alarms
resource "aws_cloudwatch_metric_alarm" "security_alarms" {
  for_each            = local.metric_filters
  alarm_name          = "${each.key}Alarm"
  alarm_description   = each.value.description
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = each.value.metric_name
  namespace           = each.value.namespace
  period             = each.value.period
  statistic          = "Sum"
  threshold          = each.value.threshold
  treat_missing_data = "notBreaching"
  
  alarm_actions = [aws_sns_topic.security_alerts.arn]
  
  tags = {
    Environment = "${var.env}"
    Purpose     = "${var.cloudscape_id}"
  }
}
