# AWS inventory permissions

Use a dedicated read-only role with temporary credentials. The initial collector needs:

- sts:GetCallerIdentity
- ec2:DescribeVolumes
- ec2:DescribeSecurityGroups
- ec2:DescribeInstances
- rds:DescribeDBInstances
- ecr:DescribeRepositories
- eks:ListClusters
- eks:DescribeCluster

Restrict the role to intended accounts and regions where supported. No access to secrets, object contents, Kubernetes credentials, or registry image contents is needed for this initial inventory. Permission denials are reported as incomplete coverage. Do not attach administrator permissions.
