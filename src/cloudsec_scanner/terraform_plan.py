"""Offline Terraform/OpenTofu plan assessment using native structured rules.

Unknown values on assessed properties withhold complete coverage. Never invoke Terraform.
"""
from dataclasses import replace
from pathlib import Path

from cloudsec_scanner.models import Finding
from cloudsec_scanner.rules.terraform import evaluate_terraform_resources
from cloudsec_scanner.safe_input import validate_document

from cloudsec_scanner.coverage import TF_FIELDS as CHECK_FIELDS, assessment, tf_status



def _unknown(value):
    if isinstance(value, dict):
        return any(_unknown(child) for child in value.values())
    if isinstance(value, list):
        return any(_unknown(child) for child in value)
    return value is True


def is_plan(document):
    return isinstance(document, dict) and "format_version" in document and any(key in document for key in ("planned_values", "resource_changes", "terraform_version"))


def scan_plan(path: Path, document: dict, assessments=None) -> tuple[list[Finding], list[str]]:
    validate_document(document)
    version = document.get("format_version")
    if not isinstance(version, str) or version.split(".")[0] != "1":
        raise ValueError("unsupported Terraform plan format")
    if document.get("errored") is True:
        raise ValueError("Terraform plan reports errors")
    warnings = []
    if document.get("complete") is False or document.get("deferred_changes"):
        warnings.append("Terraform plan is incomplete or contains deferred changes")
    changes = document.get("resource_changes", [])
    if not isinstance(changes, list):
        raise ValueError("invalid Terraform resource changes")
    unknown = {}
    for entry in changes:
        if not isinstance(entry, dict) or not isinstance(entry.get("address"), str) or not isinstance(entry.get("change"), dict):
            raise ValueError("invalid Terraform resource change")
        change = entry["change"]
        actions = change.get("actions", [])
        if not isinstance(actions, list):
            raise ValueError("invalid Terraform resource actions")
        if actions == ["delete"] or entry.get("mode") == "data":
            continue
        unknown[entry["address"]] = change.get("after_unknown", {})
    planned = document.get("planned_values")
    if not isinstance(planned, dict):
        raise ValueError("Terraform plan missing planned values")
    root = planned.get("root_module")
    if not isinstance(root, dict):
        raise ValueError("Terraform plan missing root module")
    findings = []
    seen = set()
    def walk(module):
        resources = module.get("resources", [])
        children = module.get("child_modules", [])
        if not isinstance(resources, list) or not isinstance(children, list):
            raise ValueError("invalid Terraform module")
        for item in resources:
            if not isinstance(item, dict):
                raise ValueError("invalid Terraform resource")
            if item.get("mode") == "data":
                continue
            address, kind, values = item.get("address"), item.get("type"), item.get("values")
            if not isinstance(address, str) or not address or not isinstance(kind, str) or not isinstance(values, dict):
                raise ValueError("invalid Terraform resource values")
            if address in seen:
                raise ValueError("duplicate Terraform resource address")
            seen.add(address)
            fields = CHECK_FIELDS.get(kind)
            if fields is None:
                if assessments is not None:
                    assessments.append(assessment(path, address, kind, "UNSUPPORTED", "No native predicates for this resource type"))
                continue
            unresolved = unknown.get(address, {})
            status, reason = tf_status(kind, values)
            if unresolved is True or (isinstance(unresolved, dict) and any(_unknown(unresolved.get(field)) for field in fields)):
                status, reason = "UNRESOLVED", "Plan contains unknown security-relevant values"
                warnings.append("Terraform resource has unresolved security-relevant values")
            if assessments is not None:
                assessments.append(assessment(path, address, kind, status, reason))
            # Keep full module/index address, never serialize raw plan values.
            found = evaluate_terraform_resources(path, {"resource": [{kind: {address: values}}]}, plan=True)
            findings.extend(replace(finding, resource=address) for finding in found)
        for child in children:
            if not isinstance(child, dict):
                raise ValueError("invalid Terraform child module")
            walk(child)
    walk(root)
    if set(unknown) - seen:
        warnings.append("Terraform plan omits resources present in changes")
    if not seen:
        warnings.append("Terraform plan contains no managed resources")
    return findings, warnings
