# AWS Security Monitoring Configuration
# Implements CIS Benchmark alerts for critical security events

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"  # Specify provider version for better version control
    }
  }
  required_version = ">= 1.0.0"  # Specify minimum Terraform version
}

provider "aws" {
  region = var.region
}

# Variables
variable "region" {
  type        = string
  default     = "ap-southeast-1"
  description = "AWS region for deploying resources"
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
    Environment = "Production"
    Purpose     = "Security Monitoring"
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

# Reference existing CloudWatch Log Group
data "aws_cloudwatch_log_group" "cloudtrail_logs" {
  name = var.cloudwatch_log_group
}

# Metric Filters Configuration
locals {
  metric_filters = {
    # Unauthorized API Calls Detection
    UnauthorizedAPICalls = {
      pattern      = "{($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") || ($.sourceIPAddress!=\"AWS Internal\")}"
      namespace    = "SecurityMonitoring"
      metric_name  = "UnauthorizedAPICalls"
      description  = "Detects unauthorized API calls and access denied errors"
      threshold    = 1
      period      = 300
    }

    # Root Account Usage Monitoring
    RootAccountUsage = {
      pattern      = "{($.userIdentity.type = \"Root\") && ($.userIdentity.invokedBy NOT EXISTS) && ($.eventType != \"AwsServiceEvent\")}"
      namespace    = "SecurityMonitoring"
      metric_name  = "RootAccountUsage"
      description  = "Monitors usage of root account credentials"
      threshold    = 1
      period      = 300
    }

    # IAM Policy Changes
    IAMPolicyChanges = {
      pattern      = "{($.eventName = CreatePolicy) || ($.eventName = DeletePolicy) || ($.eventName = CreatePolicyVersion) || ($.eventName = DeletePolicyVersion) || ($.eventName = AttachRolePolicy) || ($.eventName = DetachRolePolicy) || ($.eventName = AttachUserPolicy) || ($.eventName = DetachUserPolicy)}"
      namespace    = "SecurityMonitoring"
      metric_name  = "IAMPolicyChanges"
      description  = "Tracks changes to IAM policies, including creation, deletion, and attachment"
      threshold    = 1
      period      = 300
    }

    # CloudTrail Changes
    CloudTrailChanges = {
      pattern      = "{($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging)}"
      namespace    = "SecurityMonitoring"
      metric_name  = "CloudTrailChanges"
      description  = "Monitors changes to CloudTrail configuration"
      threshold    = 1
      period      = 300
    }

    # Console Sign-in Failures
    ConsoleSignInFailures = {
      pattern      = "{($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\")}"
      namespace    = "SecurityMonitoring"
      metric_name  = "ConsoleSignInFailures"
      description  = "Tracks failed console login attempts"
      threshold    = 3  # Adjusted for potential legitimate failures
      period      = 300
    }

    # Network Access Control List Changes
    NACLChanges = {
      pattern      = "{($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation)}"
      namespace    = "SecurityMonitoring"
      metric_name  = "NACLChanges"
      description  = "Detects changes to Network ACLs"
      threshold    = 1
      period      = 300
    }

    # Security Group Changes
    SecurityGroupChanges = {
      pattern      = "{($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup)}"
      namespace    = "SecurityMonitoring"
      metric_name  = "SecurityGroupChanges"
      description  = "Monitors changes to Security Groups"
      threshold    = 1
      period      = 300
    }

    # KMS Key Changes
    KMSKeyChanges = {
      pattern      = "{($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion) || ($.eventName = DeleteAlias) || ($.eventName=ImportKeyMaterial))}"
      namespace    = "SecurityMonitoring"
      metric_name  = "KMSKeyChanges"
      description  = "Tracks critical changes to KMS keys"
      threshold    = 1
      period      = 300
    }

    # S3 Bucket Policy Changes
    S3BucketPolicyChanges = {
      pattern      = "{($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication))}"
      namespace    = "SecurityMonitoring"
      metric_name  = "S3BucketPolicyChanges"
      description  = "Monitors changes to S3 bucket policies and configurations"
      threshold    = 1
      period      = 300
    }

    # VPC Changes
    VPCChanges = {
      pattern      = "{($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink)}"
      namespace    = "SecurityMonitoring"
      metric_name  = "VPCChanges"
      description  = "Tracks changes to VPC configurations and peering connections"
      threshold    = 1
      period      = 300
    }

    # Route Table Changes
    RouteTableChanges = {
      pattern      = "{($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable)}"
      namespace    = "SecurityMonitoring"
      metric_name  = "RouteTableChanges"
      description  = "Monitors changes to route tables"
      threshold    = 1
      period      = 300
    }

    # Network Gateway Changes
    NetworkGatewayChanges = {
      pattern      = "{($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway)}"
      namespace    = "SecurityMonitoring"
      metric_name  = "NetworkGatewayChanges"
      description  = "Detects changes to network gateways"
      threshold    = 1
      period      = 300
    }
  }
}
# Create Metric Filters
resource "aws_cloudwatch_metric_filter" "security_filters" {
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

# Create CloudWatch Alarms
resource "aws_cloudwatch_alarm" "security_alarms" {
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
    Environment = "Production"
    Purpose     = "Security Monitoring"
  }
}
