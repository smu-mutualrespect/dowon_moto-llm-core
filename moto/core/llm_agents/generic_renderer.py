from __future__ import annotations

import json
import re
from typing import Any

from moto.core.llm_agents.state import AgentState
from moto.core.llm_agents.xml_converter import maybe_convert_to_xml


ACCOUNT_ID = "123456789012"
REGION = "us-east-1"


def render_generic_response(state: AgentState, schema: dict[str, Any] | None) -> str | None:
    """Render a fast schema-shaped response for unknown AWS APIs.

    It only uses fields exposed by botocore's output shape. XML protocols are
    converted through botocore locationName metadata from schema.py so EC2/query
    list tags use AWS-like names such as instancesSet/item instead of member.
    """
    if not schema:
        return None
    protocol = schema.get("protocol")
    if protocol not in {"json", "rest-json", "query", "ec2"}:
        return None
    output_schema = schema.get("output_schema")
    if not isinstance(output_schema, dict):
        return "{}"
    if not output_schema:
        return None
    rendered = {
        name: _render_value(
            name,
            shape,
            service=state["service"],
            action=state["action"],
            depth=0,
        )
        for name, shape in output_schema.items()
    }
    if protocol in {"query", "ec2"}:
        return maybe_convert_to_xml(rendered, schema)
    return json.dumps(rendered, separators=(",", ":"))


def _render_value(name: str, shape: Any, *, service: str, action: str, depth: int) -> Any:
    if depth > 4:
        return _fallback_scalar(name, service, action)
    if isinstance(shape, dict):
        # Botocore map shapes are represented as {"<key>": ..., "<value>": ...}.
        if set(shape) == {"<key>", "<value>"}:
            return {"Environment": _render_value("Environment", shape["<value>"], service=service, action=action, depth=depth + 1)}
        return {
            field: _render_value(field, field_shape, service=service, action=action, depth=depth + 1)
            for field, field_shape in shape.items()
            if not field.startswith("_")
        }
    if isinstance(shape, list):
        member_shape = shape[0] if shape else "string"
        return [_render_value(_singularize(name), member_shape, service=service, action=action, depth=depth + 1)]
    if isinstance(shape, str):
        return _render_scalar(name, shape, service, action)
    return _fallback_scalar(name, service, action)


def _render_scalar(name: str, type_name: str, service: str, action: str) -> Any:
    lowered = name.lower()
    if type_name in {"integer", "long"}:
        if "time" in lowered or lowered.endswith("at"):
            return 1704067200
        if "size" in lowered or "count" in lowered:
            return 2
        return 1
    if type_name in {"float", "double"}:
        return 1704067200.0 if "time" in lowered or lowered.endswith("at") else 1.0
    if type_name == "boolean":
        return False
    if type_name == "timestamp":
        return 1704067200.0
    if type_name in {"blob", "bytes"}:
        return "ZXhhbXBsZQ=="
    if type_name == "string":
        return _fallback_scalar(name, service, action)
    return _fallback_scalar(name, service, action)


def _fallback_scalar(name: str, service: str, action: str) -> Any:
    lowered = name.lower()
    resource = _resource_name(action)
    special = _special_scalar(lowered, service, resource)
    if special is not None:
        return special
    if lowered in {"active"}:
        return True
    if lowered.endswith("count") or lowered in {"count", "instancecount"}:
        return 1
    if (
        lowered.endswith("price")
        or lowered.endswith("amount")
        or lowered in {"amount", "fixedprice", "usageprice"}
    ):
        return 1.0
    if lowered in {"duration", "term"}:
        return 31536000
    if lowered == "arn" or lowered.endswith("arn"):
        if service == "healthlake" and "datastore" in lowered:
            return f"arn:aws:healthlake:{REGION}:{ACCOUNT_ID}:datastore/fhir/hl-0a1b2c3d4e5f67890"
        return f"arn:aws:{service}:{REGION}:{ACCOUNT_ID}:{resource}/prod-{resource}-01"
    if lowered.endswith("id") or lowered == "id":
        if "instance" in lowered:
            return "i-1234567890abcdef0"
        if "volume" in lowered:
            return "vol-1234567890abcdef0"
        if "reservation" in lowered:
            return "r-0a1b2c3d4e5f67890"
        prefix = re.sub(r"[^a-z0-9]", "", service.lower())[:8] or "res"
        return f"{prefix}-0a1b2c3d4e5f67890"
    if "account" in lowered and lowered.endswith("id"):
        return ACCOUNT_ID
    if lowered in {"createdtime", "createdat", "lastupdatedtime", "lastupdatedat", "lastseentime"}:
        return "2024-01-01T00:00:00Z"
    if lowered in {"nexttoken", "nextpageToken".lower()}:
        return ""
    if "status" in lowered:
        return _status_for(service)
    if "state" in lowered:
        return _state_for(service, action)
    if "type" in lowered:
        return resource.upper()
    if "name" in lowered:
        return f"prod-{resource}-01"
    if "description" in lowered:
        return f"Production {resource} resource"
    if "url" in lowered or "endpoint" in lowered:
        return f"https://{service}.{REGION}.amazonaws.com/{resource}/prod-{resource}-01"
    return f"prod-{resource}-01"


def _special_scalar(name: str, service: str, resource: str) -> str | None:
    if service == "healthlake":
        if name == "datastoreid":
            return "hl-0a1b2c3d4e5f67890"
        if name == "datastoretypeversion":
            return "R4"
        if name == "datastoreendpoint":
            return f"https://healthlake.{REGION}.amazonaws.com/datastore/hl-0a1b2c3d4e5f67890/r4/"
        if name == "cmktype":
            return "AWS_OWNED_KMS_KEY"
        if name == "kmskeyid":
            return ""
        if name == "preloaddatatype":
            return "SYNTHEA"
        if name == "authorizationstrategy":
            return "AWS_AUTH"
        if name in {"metadata", "idplambdaarn", "errormessage", "errorcategory"}:
            return ""
    if service == "appflow":
        if name in {"sourceconnectortype", "sourceconnectorlabel"}:
            return "Salesforce"
        if name in {"destinationconnectortype", "destinationconnectorlabel"}:
            return "S3"
        if name == "triggertype":
            return "Scheduled"
        if name in {"createdby", "lastupdatedby"}:
            return f"arn:aws:iam::{ACCOUNT_ID}:user/data-ops"
        if name == "mostrecentexecutionstatus":
            return "Successful"
        if name == "mostrecentexecutionmessage":
            return "Execution completed successfully"
    if service == "backup-gateway":
        if name == "gatewaytype":
            return "BACKUP_VM"
        if name == "gatewaydisplayname":
            return "prod-backup-gateway-01"
    if service == "billingconductor":
        if name == "billinggrouptype":
            return "PRIMARY"
        if name == "pricingplanarn":
            return f"arn:aws:billingconductor::{ACCOUNT_ID}:pricingplan/prod-pricing-plan"
    if service == "ec2":
        if name == "monitoring":
            return "enabled"
        if name == "currencycode":
            return "USD"
        if name == "instancetype":
            return "t3.micro"
        if name == "availabilityzone":
            return f"{REGION}a"
        if name == "availabilityzoneid":
            return "use1-az1"
        if name == "offeringclass":
            return "standard"
        if name == "offeringtype":
            return "All Upfront"
        if name == "instancetenancy":
            return "default"
        if name == "scope":
            return "Availability Zone"
        if name == "productdescription":
            return "Linux/UNIX"
        if name == "reservedinstancesid":
            return "ri-0a1b2c3d4e5f67890"
        if name == "spotdatafeedsubscriptionid":
            return "sdf-0a1b2c3d4e5f67890"
        if name == "bucket":
            return "my-honeypot-bucket"
        if name == "prefix":
            return "spot-datafeed/"
    return None


def _resource_name(action: str) -> str:
    name = re.sub(r"^(List|Get|Describe)", "", action or "", flags=re.IGNORECASE)
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", name).lower()
    name = name.strip("-") or "resource"
    if name.endswith("s"):
        name = name[:-1]
    return name


def _singularize(name: str) -> str:
    if name.endswith("ies"):
        return name[:-3] + "y"
    if name.endswith("s"):
        return name[:-1]
    return name


def _status_for(service: str) -> str:
    if service in {"appflow"}:
        return "Active"
    if service in {"proton"}:
        return "SUCCEEDED"
    return "ACTIVE"


def _state_for(service: str, action: str) -> str:
    if service == "ec2":
        if action in {"MonitorInstances", "UnmonitorInstances"}:
            return "enabled" if action == "MonitorInstances" else "disabled"
        if "ReservedInstances" in action:
            return "active"
        if "Volume" in action:
            return "ok"
    return "active"
