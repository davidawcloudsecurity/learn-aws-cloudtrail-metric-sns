# learn-aws-cloudtrail-metric-sns
how to deploy cloudtrail with metric filter and sns
## https://developer.hashicorp.com/terraform/install
Install if running at cloudshell
```ruby
alias k=kubectl; alias tf="terraform"; alias tfa="terraform apply --auto-approve"; alias tfd="terraform destroy --auto-approve"; alias tfm="terraform init; terraform fmt; terraform validate; terraform plan"; sudo yum install -y yum-utils shadow-utils; sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo; sudo yum -y install terraform; terraform init
```
## How to Use Terraform Variables: Examples
```bash
tfa -var project_account_id=$project_account -var platform_account_id=$platform_account -var project_iam_role=$example_role;
```

