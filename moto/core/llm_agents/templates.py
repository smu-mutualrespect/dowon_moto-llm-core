from __future__ import annotations

import json
import hashlib
from typing import Any

from moto.core.llm_agents.state import AgentState


ACCOUNT_ID = "123456789012"
REGION = "us-east-1"


def render_template_response(state: AgentState, schema: dict[str, Any] | None) -> str | None:
    service = state["service"].lower()
    action = _normalize_action(state["action"])
    body = state.get("body", {})
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

    if service == "sts" and action == "decodeauthorizationmessage":
        decoded = json.dumps(
            {
                "allowed": False,
                "explicitDeny": False,
                "matchedStatements": [],
                "failures": [],
                "context": {
                    "principal": {
                        "id": "AIDAEXAMPLEAUDIT",
                        "arn": f"arn:aws:iam::{ACCOUNT_ID}:user/prod-audit",
                    },
                    "action": "iam:AttachUserPolicy",
                    "resource": f"arn:aws:iam::{ACCOUNT_ID}:user/prod-audit",
                    "conditions": {
                        "items": [
                            {
                                "key": "aws:PrincipalArn",
                                "values": [f"arn:aws:iam::{ACCOUNT_ID}:user/prod-audit"],
                            }
                        ]
                    },
                },
            },
            separators=(",", ":"),
        )
        return _xml(
            "DecodeAuthorizationMessageResponse",
            "<DecodeAuthorizationMessageResult>"
            f"<DecodedMessage>{_xml_escape(decoded)}</DecodedMessage>"
            "</DecodeAuthorizationMessageResult>",
            "https://sts.amazonaws.com/doc/2011-06-15/",
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

    if service == "iam" and action == "getcontextkeysforprincipalpolicy":
        members = "".join(
            f"<member>{_xml_escape(name)}</member>"
            for name in [
                "aws:PrincipalArn",
                "aws:username",
                "aws:CurrentTime",
                "aws:SourceIp",
            ]
        )
        return _xml(
            "GetContextKeysForPrincipalPolicyResponse",
            "<GetContextKeysForPrincipalPolicyResult>"
            f"<ContextKeyNames>{members}</ContextKeyNames>"
            "</GetContextKeysForPrincipalPolicyResult>",
        )

    if service == "iam" and action == "listservicespecificcredentials":
        user = str(_body_value(body, "UserName") or "victim-admin")
        return _xml(
            "ListServiceSpecificCredentialsResponse",
            "<ListServiceSpecificCredentialsResult>"
            "<ServiceSpecificCredentials>"
            "<member>"
            f"<UserName>{_xml_escape(user)}</UserName>"
            "<Status>Active</Status>"
            "<ServiceUserName>victim-admin@example.com</ServiceUserName>"
            "<CreateDate>2024-02-20T04:12:00Z</CreateDate>"
            "<ServiceSpecificCredentialId>ACCAEXAMPLESERVICE01</ServiceSpecificCredentialId>"
            "<ServiceName>codecommit.amazonaws.com</ServiceName>"
            "</member>"
            "</ServiceSpecificCredentials>"
            "</ListServiceSpecificCredentialsResult>",
        )

    if service == "iam" and action == "generateservicelastaccesseddetails":
        target_arn = str(_body_value(body, "Arn") or f"arn:aws:iam::{ACCOUNT_ID}:user/victim-admin")
        stable = _stable_suffix(target_arn)
        return _xml(
            "GenerateServiceLastAccessedDetailsResponse",
            "<GenerateServiceLastAccessedDetailsResult>"
            f"<JobId>job-{stable}</JobId>"
            "</GenerateServiceLastAccessedDetailsResult>",
        )

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

    if service == "ecr" and action == "batchchecklayeravailability":
        repository = str(_body_value(body, "repositoryName") or "demo")
        digest = _first_value(_body_value(body, "layerDigests")) or _fake_digest(repository)
        return json.dumps(
            {
                "layers": [
                    {
                        "layerDigest": digest,
                        "layerAvailability": "AVAILABLE",
                        "layerSize": 7340032,
                        "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                    }
                ],
                "failures": [],
            },
            separators=(",", ":"),
        )

    if service == "ecr" and action == "getdownloadurlforlayer":
        repository = str(_body_value(body, "repositoryName") or "demo")
        digest = str(_body_value(body, "layerDigest") or _fake_digest(repository))
        return json.dumps(
            {
                "downloadUrl": f"https://prod-ecr-layers.s3.{REGION}.amazonaws.com/{repository}/{digest.replace(':', '-')}.tar.gz?X-Amz-Expires=900",
                "layerDigest": digest,
            },
            separators=(",", ":"),
        )

    if service == "ecr" and action == "initiatelayerupload":
        repository = str(_body_value(body, "repositoryName") or "demo")
        return json.dumps(
            {
                "uploadId": f"upload-{_stable_suffix(repository)}",
                "partSize": 10485760,
            },
            separators=(",", ":"),
        )

    if service == "ecr" and action == "completelayerupload":
        repository = str(_body_value(body, "repositoryName") or "demo")
        upload_id = str(_body_value(body, "uploadId") or f"upload-{_stable_suffix(repository)}")
        digest = _first_value(_body_value(body, "layerDigests")) or _fake_digest(repository)
        return json.dumps(
            {
                "registryId": ACCOUNT_ID,
                "repositoryName": repository,
                "uploadId": upload_id,
                "layerDigest": digest,
            },
            separators=(",", ":"),
        )

    if service == "secretsmanager" and action == "validateresourcepolicy":
        policy = str(_body_value(body, "ResourcePolicy") or "")
        broad = _looks_like_broad_secret_policy(policy)
        return json.dumps(
            {
                "PolicyValidationPassed": not broad,
                "ValidationErrors": (
                    [
                        {
                            "CheckName": "BroadAccessCheck",
                            "ErrorMessage": "Resource policy grants access to a broad principal.",
                        }
                    ]
                    if broad
                    else []
                ),
            },
            separators=(",", ":"),
        )

    return None


def _normalize_action(action: str) -> str:
    return "".join(ch for ch in action.lower() if ch.isalnum())


def _xml(root: str, inner: str, xmlns: str = "https://iam.amazonaws.com/doc/2010-05-08/") -> str:
    return f"<{root} xmlns=\"{xmlns}\">{inner}<ResponseMetadata><RequestId>00000000-0000-0000-0000-000000000000</RequestId></ResponseMetadata></{root}>"


def _body_value(body: dict[str, Any], key: str) -> Any:
    if key in body:
        return body[key]
    normalized = _normalize_action(key)
    for candidate_key, value in body.items():
        if _normalize_action(str(candidate_key)) == normalized:
            return value
    return None


def _first_value(value: Any) -> str | None:
    if isinstance(value, list) and value:
        return str(value[0])
    if value:
        return str(value)
    return None


def _fake_digest(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _stable_suffix(value: str) -> str:
    cleaned = "".join(ch.lower() for ch in value if ch.isalnum())
    return (cleaned[-16:] or "0000000000000000").rjust(16, "0")


def _xml_escape(value: Any) -> str:
    text = str(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def _decoy_value(decoys: list[dict[str, str]], decoy_type: str) -> str | None:
    for decoy in decoys:
        if decoy.get("decoy_type") == decoy_type:
            return decoy.get("decoy_value")
    return None


def _looks_like_broad_secret_policy(policy: str) -> bool:
    try:
        parsed = json.loads(policy)
    except Exception:
        return False
    statements = parsed.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        action = statement.get("Action")
        actions = action if isinstance(action, list) else [action]
        if principal == "*" or principal == {"AWS": "*"}:
            if "*" in actions or "secretsmanager:GetSecretValue" in actions:
                return True
    return False
