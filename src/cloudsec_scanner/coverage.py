"""Explicit resource-level coverage for native IaC checks.

EVALUATED means applicable native predicates ran, not benchmark compliance.
Unsupported types and unresolved values withhold overall completion.
"""
from pathlib import Path

# These fields correspond to implemented Terraform predicates, not all provider properties.
TF_FIELDS = {
    "aws_s3_bucket_acl": {"acl"},
    "aws_s3_bucket": {"acl", "force_destroy"},
    "aws_security_group_rule": {"type", "cidr_blocks", "ipv6_cidr_blocks"},
    "aws_vpc_security_group_ingress_rule": {"cidr_ipv4", "cidr_ipv6"},
    "aws_security_group": {"ingress"},
    "aws_ebs_volume": {"encrypted"},
    "aws_db_instance": {"storage_encrypted", "publicly_accessible"},
    "aws_iam_policy": {"policy"},
    "aws_iam_role_policy": {"policy"},
    "aws_iam_user_policy": {"policy"},
    "aws_iam_group_policy": {"policy"},
    "azurerm_storage_account": {"enable_https_traffic_only", "https_traffic_only_enabled", "allow_nested_items_to_be_public", "min_tls_version"},
    "google_storage_bucket_iam_member": {"member", "members"},
    "google_storage_bucket_iam_binding": {"member", "members"},
    "google_compute_firewall": {"source_ranges", "allow", "allowed"},
    "aws_s3_bucket_public_access_block": {"block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets"},
    "aws_eks_cluster": {"vpc_config"},
    "aws_ecr_repository": {"image_tag_mutability"},
    "google_storage_bucket": {"public_access_prevention", "uniform_bucket_level_access"},
    "google_sql_database_instance": {"settings"},
}

CF_FIELDS = {
    "AWS::S3::Bucket": {"PublicReadAccess", "PublicAccessBlockConfiguration", "BucketEncryption"},
    "AWS::RDS::DBInstance": {"PubliclyAccessible", "StorageEncrypted"},
    "AWS::EC2::SecurityGroup": {"SecurityGroupIngress"},
    "AWS::EC2::SecurityGroupIngress": {"CidrIp", "CidrIpv6", "IpProtocol", "FromPort", "ToPort"},
}
ARM_FIELDS = {
    "microsoft.storage/storageaccounts": {"supportsHttpsTrafficOnly", "allowBlobPublicAccess", "minimumTlsVersion"},
    "microsoft.sql/servers/firewallrules": {"startIpAddress", "endIpAddress"},
}
WORKLOADS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "ReplicationController"}
NON_WORKLOADS = {"Service", "ConfigMap", "Namespace", "ServiceAccount", "PersistentVolumeClaim"}


def unresolved(value):
    if isinstance(value, str):
        return "${" in value or "{{" in value or (value.startswith("[") and value.endswith("]")) or value.startswith("$(")
    if isinstance(value, dict):
        return any(str(k) in {"Ref", "Condition"} or str(k).startswith("Fn::") or unresolved(v) for k, v in value.items())
    if isinstance(value, list):
        return any(unresolved(v) for v in value)
    return False


def assessment(path, resource, resource_type, status, reason=""):
    return {"path": str(path), "resource_id": resource, "resource_type": resource_type, "status": status, "reason": reason}


def tf_status(kind, body):
    fields = TF_FIELDS.get(kind)
    if fields is None:
        return "UNSUPPORTED", "No native predicates for this resource type"
    if any(unresolved(body.get(field)) for field in fields):
        return "UNRESOLVED", "Security-relevant expression requires resolved plan values"
    required = {"aws_ebs_volume": "encrypted", "aws_db_instance": "storage_encrypted"}
    if kind in required and type(body.get(required[kind])) is not bool:
        return "UNRESOLVED", "Explicit security property unavailable"
    return "EVALUATED", "Native predicates evaluated; not a full benchmark assessment"


def kube_id(doc):
    metadata = doc.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}
    return "/".join(str(v) for v in (doc.get("apiVersion", "unknown"), doc.get("kind", "unknown"), metadata.get("namespace", "default"), metadata.get("name", "unknown")))


def structured_coverage(path: Path, doc):
    if not isinstance(doc, dict):
        return []
    entries = []
    if "apiVersion" in doc and "kind" in doc:
        kind = doc["kind"]
        if kind in WORKLOADS or kind in {"Role", "ClusterRole"}:
            status = "UNRESOLVED" if unresolved(doc.get("spec", {})) or unresolved(doc.get("rules", [])) else "EVALUATED"
        elif kind in NON_WORKLOADS:
            status = "NOT_APPLICABLE"
        else:
            status = "UNSUPPORTED"
        entries.append(assessment(path, kube_id(doc), str(kind), status))
    if isinstance(doc.get("Resources"), dict):
        for name, resource in doc["Resources"].items():
            if not isinstance(resource, dict):
                entries.append(assessment(path, str(name), "unknown", "UNRESOLVED"))
                continue
            kind = str(resource.get("Type", "unknown"))
            props = resource.get("Properties", {})
            fields = CF_FIELDS.get(kind)
            status = "UNSUPPORTED" if fields is None else "UNRESOLVED" if not isinstance(props, dict) or any(unresolved(props.get(k)) for k in fields) else "EVALUATED"
            entries.append(assessment(path, kind + "." + str(name), kind, status))
    resources = doc.get("resources")
    if isinstance(resources, list):
        for index, resource in enumerate(resources):
            if not isinstance(resource, dict):
                continue
            kind = str(resource.get("type", "unknown"))
            if kind.lower().startswith("microsoft.") or "management.azure.com" in str(doc.get("$schema", "")):
                fields = ARM_FIELDS.get(kind.lower())
            elif "storage" in kind.lower() and "bucket" in kind.lower():
                fields = {"iamConfiguration", "uniformBucketLevelAccess"}
            else:
                fields = None
            props = resource.get("properties", {})
            status = "UNSUPPORTED" if fields is None else "UNRESOLVED" if not isinstance(props, dict) or any(unresolved(props.get(k)) for k in fields) else "EVALUATED"
            entries.append(assessment(path, kind + "." + str(resource.get("name", index)), kind, status))
    if "sourceRanges" in doc and "allowed" in doc:
        entries.append(assessment(path, str(doc.get("name", "firewall")), "gcp-firewall", "UNRESOLVED" if unresolved(doc.get("sourceRanges")) or unresolved(doc.get("allowed")) else "EVALUATED"))
    return entries
