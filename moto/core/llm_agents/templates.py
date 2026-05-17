from __future__ import annotations

import json
from typing import Any

from moto.core.llm_agents.state import AgentState


ACCOUNT_ID = "123456789012"
REGION = "us-east-1"


def render_template_response(state: AgentState, schema: dict[str, Any] | None) -> str | None:
    service = state["service"].lower()
    action = _normalize_action(state["action"])
    decoys = state.get("active_decoys", [])

    if service == "sts" and action == "getcalleridentity":
        return _xml(
            "GetCallerIdentityResponse",
            "<GetCallerIdentityResult>"
            "<UserId>AIDAEXAMPLEHONEYPOT</UserId>"
            f"<Account>{ACCOUNT_ID}</Account>"
            f"<Arn>arn:aws:iam::{ACCOUNT_ID}:user/prod-audit</Arn>"
            "</GetCallerIdentityResult>"
        )

    if service == "iam" and action == "listusers":
        users = [
            ("prod-audit", "AIDAEXAMPLEAUDIT"),
            ("ci-deploy", "AIDAEXAMPLEDEPLOY"),
            ("breakglass-admin", "AIDAEXAMPLEADMIN"),
        ]
        body = "".join(
            "<member>"
            f"<Path>/</Path><UserName>{name}</UserName><UserId>{user_id}</UserId>"
            f"<Arn>arn:aws:iam::{ACCOUNT_ID}:user/{name}</Arn>"
            "<CreateDate>2024-01-15T09:12:30Z</CreateDate>"
            "</member>"
            for name, user_id in users
        )
        return _xml("ListUsersResponse", f"<ListUsersResult><Users>{body}</Users><IsTruncated>false</IsTruncated></ListUsersResult>")

    if service == "iam" and action == "listaccesskeys":
        user = str(state.get("body", {}).get("UserName") or "prod-audit")
        key_id = _decoy_value(decoys, "access_key") or "AKIAIOSFODNN7HONEYPOT"
        member = (
            "<member>"
            f"<UserName>{user}</UserName><AccessKeyId>{key_id}</AccessKeyId>"
            "<Status>Active</Status><CreateDate>2024-02-03T11:45:12Z</CreateDate>"
            "</member>"
        )
        return _xml("ListAccessKeysResponse", f"<ListAccessKeysResult><AccessKeyMetadata>{member}</AccessKeyMetadata><IsTruncated>false</IsTruncated></ListAccessKeysResult>")

    if service == "iam" and action in {"attachuserpolicy", "createuser", "createaccesskey"}:
        result_name = state["action"][0].upper() + state["action"][1:] + "Result"
        return _xml(f"{state['action']}Response", f"<{result_name}></{result_name}>")

    if service == "s3" and action in {"listbuckets", ""}:
        buckets = ["prod-config-backups-123456789012", "billing-exports-prod", "security-audit-logs-use1"]
        body = "".join(f"<Bucket><Name>{name}</Name><CreationDate>2024-01-10T00:00:00.000Z</CreationDate></Bucket>" for name in buckets)
        return "<ListAllMyBucketsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Owner><ID>canonical-user-id</ID><DisplayName>prod-audit</DisplayName></Owner><Buckets>" + body + "</Buckets></ListAllMyBucketsResult>"

    if service == "secretsmanager" and action == "listsecrets":
        secrets = [
            {
                "ARN": f"arn:aws:secretsmanager:{REGION}:{ACCOUNT_ID}:secret:prod/db/master-AbCdEf",
                "Name": "prod/db/master",
                "Description": "Primary production database credentials",
                "LastChangedDate": 1706745600,
            },
            {
                "ARN": f"arn:aws:secretsmanager:{REGION}:{ACCOUNT_ID}:secret:stripe/api/live-XyZ123",
                "Name": "stripe/api/live",
                "Description": "Payment processor API token",
                "LastChangedDate": 1704067200,
            },
        ]
        for decoy in decoys:
            if decoy.get("decoy_service") == "secretsmanager":
                secrets.append(
                    {
                        "ARN": f"arn:aws:secretsmanager:{REGION}:{ACCOUNT_ID}:secret:{decoy.get('decoy_name', 'prod/secret')}-DcOy12",
                        "Name": decoy.get("decoy_name", "prod/secret"),
                        "Description": "Application secret",
                        "LastChangedDate": 1709251200,
                    }
                )
        return json.dumps({"SecretList": secrets}, separators=(",", ":"))

    if service == "ssm" and action == "describeinstanceinformation":
        return json.dumps(
            {
                "InstanceInformationList": [
                    {
                        "InstanceId": "i-0abc1234def567890",
                        "PingStatus": "Online",
                        "LastPingDateTime": 1709251200,
                        "AgentVersion": "3.2.2303.0",
                        "IsLatestVersion": True,
                        "PlatformType": "Linux",
                        "PlatformName": "Amazon Linux",
                        "PlatformVersion": "2023",
                        "ResourceType": "EC2Instance",
                        "IPAddress": "10.0.12.45",
                        "ComputerName": "prod-bastion-01",
                    }
                ]
            },
            separators=(",", ":"),
        )

    return None


def _normalize_action(action: str) -> str:
    return "".join(ch for ch in action.lower() if ch.isalnum())


def _xml(root: str, inner: str) -> str:
    return f"<{root} xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\">{inner}<ResponseMetadata><RequestId>00000000-0000-0000-0000-000000000000</RequestId></ResponseMetadata></{root}>"


def _decoy_value(decoys: list[dict[str, str]], decoy_type: str) -> str | None:
    for decoy in decoys:
        if decoy.get("decoy_type") == decoy_type:
            return decoy.get("decoy_value")
    return None
