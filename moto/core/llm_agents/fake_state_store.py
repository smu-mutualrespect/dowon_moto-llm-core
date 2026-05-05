from __future__ import annotations

import copy
import threading
from typing import Any


ACCOUNT_ID = "123456789012"
REGION = "us-east-1"

_lock = threading.RLock()
_worlds: dict[str, dict[str, Any]] = {}


def get_world(session_id: str) -> dict[str, Any]:
    with _lock:
        if session_id not in _worlds:
            _worlds[session_id] = _new_world()
        return _worlds[session_id]


def snapshot_world(session_id: str) -> dict[str, Any]:
    with _lock:
        return copy.deepcopy(get_world(session_id))


def apply_decoy(session_id: str, decoy: dict[str, str]) -> None:
    with _lock:
        world = get_world(session_id)
        service = decoy.get("decoy_service", "")
        decoy_type = decoy.get("decoy_type", "")
        name = decoy.get("decoy_name", "prod-decoy")
        value = decoy.get("decoy_value", "")

        if service == "iam" and decoy_type == "role":
            world["roles"].setdefault(
                name,
                {
                    "role_id": _role_id(name),
                    "arn": f"arn:aws:iam::{ACCOUNT_ID}:role/{name}",
                    "path": "/",
                    "created": "2024-02-14T08:30:00Z",
                    "policies": ["AdministratorAccess"],
                },
            )
        elif service == "iam" and decoy_type == "access_key":
            user = world["users"].setdefault("breakglass-admin", _user("breakglass-admin", "AIDAEXAMPLEADMIN"))
            user["access_keys"].append(
                {
                    "id": value or "AKIADEC0YACCESSKEY01",
                    "status": "Active",
                    "created": "2024-03-01T10:15:00Z",
                }
            )
        elif service == "s3" and decoy_type == "bucket":
            world["buckets"].setdefault(
                name,
                {
                    "created": "2024-01-10T00:00:00.000Z",
                    "objects": [
                        {"key": "prod.env", "size": 218, "last_modified": "2024-03-03T12:21:00.000Z"},
                        {"key": "iam/backup-users.csv", "size": 1542, "last_modified": "2024-03-04T01:05:00.000Z"},
                    ],
                },
            )
        elif service == "secretsmanager" and decoy_type == "secret":
            world["secrets"].setdefault(
                name,
                {
                    "arn": f"arn:aws:secretsmanager:{REGION}:{ACCOUNT_ID}:secret:{name}-DcOy12",
                    "description": "Application secret",
                    "last_changed": 1709251200,
                    "value": value or "postgres://prod_admin:REDACTED@db.internal:5432/app",
                },
            )
        elif service == "ssm" and decoy_type == "parameter":
            world["parameters"].setdefault(
                name,
                {
                    "name": name,
                    "type": "SecureString",
                    "value": value or "AKIADEC0YPARAMETER01",
                    "version": 3,
                    "last_modified": 1709251200,
                },
            )


def _new_world() -> dict[str, Any]:
    return {
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "caller": "prod-audit",
        "users": {
            "prod-audit": _user("prod-audit", "AIDAEXAMPLEAUDIT"),
            "ci-deploy": _user("ci-deploy", "AIDAEXAMPLEDEPLOY"),
            "breakglass-admin": _user("breakglass-admin", "AIDAEXAMPLEADMIN"),
        },
        "roles": {
            "ProdReadOnly": {
                "role_id": "AROAREADONLY0000001",
                "arn": f"arn:aws:iam::{ACCOUNT_ID}:role/ProdReadOnly",
                "path": "/",
                "created": "2024-01-22T06:30:00Z",
                "policies": ["ReadOnlyAccess"],
            },
            "DeployAdmin": {
                "role_id": "AROADMIN000000001",
                "arn": f"arn:aws:iam::{ACCOUNT_ID}:role/DeployAdmin",
                "path": "/service-role/",
                "created": "2024-02-03T03:14:00Z",
                "policies": ["AdministratorAccess"],
            },
        },
        "buckets": {
            "prod-config-backups-123456789012": {
                "created": "2024-01-10T00:00:00.000Z",
                "objects": [
                    {"key": "terraform.tfstate", "size": 84121, "last_modified": "2024-03-02T02:03:00.000Z"},
                    {"key": "eks/prod/kubeconfig.bak", "size": 6402, "last_modified": "2024-02-28T14:20:00.000Z"},
                ],
            },
            "billing-exports-prod": {
                "created": "2024-01-12T00:00:00.000Z",
                "objects": [
                    {"key": "cur/2024-03/report.parquet", "size": 7340032, "last_modified": "2024-03-05T00:12:00.000Z"},
                ],
            },
            "security-audit-logs-use1": {
                "created": "2024-01-14T00:00:00.000Z",
                "objects": [
                    {"key": "cloudtrail/AWSLogs/123456789012/2024/03/05/log.json.gz", "size": 93488, "last_modified": "2024-03-05T11:55:00.000Z"},
                ],
            },
        },
        "secrets": {
            "prod/db/master": {
                "arn": f"arn:aws:secretsmanager:{REGION}:{ACCOUNT_ID}:secret:prod/db/master-AbCdEf",
                "description": "Primary production database credentials",
                "last_changed": 1706745600,
                "value": '{"username":"prod_admin","password":"REDACTED","host":"db-prod.internal"}',
            },
            "stripe/api/live": {
                "arn": f"arn:aws:secretsmanager:{REGION}:{ACCOUNT_ID}:secret:stripe/api/live-XyZ123",
                "description": "Payment processor API token",
                "last_changed": 1704067200,
                "value": "sk_live_REDACTED",
            },
        },
        "parameters": {
            "/prod/db/password": {
                "name": "/prod/db/password",
                "type": "SecureString",
                "value": "REDACTED",
                "version": 7,
                "last_modified": 1709251200,
            },
        },
        "instances": [
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
        ],
    }


def _user(name: str, user_id: str) -> dict[str, Any]:
    return {
        "name": name,
        "id": user_id,
        "arn": f"arn:aws:iam::{ACCOUNT_ID}:user/{name}",
        "path": "/",
        "created": "2024-01-15T09:12:30Z",
        "policies": ["ReadOnlyAccess"] if name != "breakglass-admin" else ["AdministratorAccess"],
        "access_keys": [
            {
                "id": "AKIAIOSFODNN7HONEYPOT" if name == "prod-audit" else f"AKIA{name.replace('-', '').upper()[:12]:0<12}",
                "status": "Active",
                "created": "2024-02-03T11:45:12Z",
            }
        ],
    }


def _role_id(name: str) -> str:
    cleaned = "".join(ch for ch in name.upper() if ch.isalnum())[:12]
    return f"AROA{cleaned:0<12}"
