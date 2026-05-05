from __future__ import annotations

import json
from typing import Any

from moto.core.llm_agents.fake_state_store import get_world
from moto.core.llm_agents.state import AgentState


def render_state_response(state: AgentState, schema: dict[str, Any] | None) -> str | None:
    world = get_world(state["session_id"])
    service = state["service"].lower()
    action = _normalize_action(state["action"])
    body = state.get("body", {})

    if service == "sts" and action == "getcalleridentity":
        caller = world["users"][world["caller"]]
        return _xml(
            "GetCallerIdentityResponse",
            "<GetCallerIdentityResult>"
            f"<UserId>{caller['id']}</UserId>"
            f"<Account>{world['account_id']}</Account>"
            f"<Arn>{caller['arn']}</Arn>"
            "</GetCallerIdentityResult>",
            "https://sts.amazonaws.com/doc/2011-06-15/",
        )

    if service == "iam" and action == "listusers":
        members = "".join(_iam_user_member(user) for user in world["users"].values())
        return _iam_xml("ListUsersResponse", f"<ListUsersResult><Users>{members}</Users><IsTruncated>false</IsTruncated></ListUsersResult>")

    if service == "iam" and action == "getuser":
        user_name = str(body.get("UserName") or world["caller"])
        user = world["users"].get(user_name)
        if not user:
            user = _ensure_user(world, user_name)
        return _iam_xml("GetUserResponse", f"<GetUserResult><User>{_iam_user_fields(user)}</User></GetUserResult>")

    if service == "iam" and action == "createuser":
        user_name = str(body.get("UserName") or "temp-operator")
        user = _ensure_user(world, user_name)
        return _iam_xml("CreateUserResponse", f"<CreateUserResult><User>{_iam_user_fields(user)}</User></CreateUserResult>")

    if service == "iam" and action == "listaccesskeys":
        user_name = str(body.get("UserName") or world["caller"])
        user = world["users"].get(user_name) or _ensure_user(world, user_name)
        members = "".join(
            "<member>"
            f"<UserName>{user_name}</UserName><AccessKeyId>{key['id']}</AccessKeyId>"
            f"<Status>{key['status']}</Status><CreateDate>{key['created']}</CreateDate>"
            "</member>"
            for key in user["access_keys"]
        )
        return _iam_xml("ListAccessKeysResponse", f"<ListAccessKeysResult><AccessKeyMetadata>{members}</AccessKeyMetadata><IsTruncated>false</IsTruncated></ListAccessKeysResult>")

    if service == "iam" and action == "createaccesskey":
        user_name = str(body.get("UserName") or world["caller"])
        user = world["users"].get(user_name) or _ensure_user(world, user_name)
        key_id = f"AKIA{user_name.replace('-', '').upper()[:12]:0<12}{len(user['access_keys']) + 1:02d}"
        key = {"id": key_id, "status": "Active", "created": "2024-03-05T12:00:00Z"}
        user["access_keys"].append(key)
        return _iam_xml(
            "CreateAccessKeyResponse",
            "<CreateAccessKeyResult><AccessKey>"
            f"<UserName>{user_name}</UserName><AccessKeyId>{key_id}</AccessKeyId>"
            "<Status>Active</Status><SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYFAKEKEY</SecretAccessKey>"
            "<CreateDate>2024-03-05T12:00:00Z</CreateDate>"
            "</AccessKey></CreateAccessKeyResult>",
        )

    if service == "iam" and action == "listroles":
        members = "".join(
            "<member>"
            f"<Path>{role['path']}</Path><RoleName>{name}</RoleName><RoleId>{role['role_id']}</RoleId>"
            f"<Arn>{role['arn']}</Arn><CreateDate>{role['created']}</CreateDate>"
            "</member>"
            for name, role in world["roles"].items()
        )
        return _iam_xml("ListRolesResponse", f"<ListRolesResult><Roles>{members}</Roles><IsTruncated>false</IsTruncated></ListRolesResult>")

    if service == "iam" and action == "attachuserpolicy":
        user_name = str(body.get("UserName") or world["caller"])
        policy_arn = str(body.get("PolicyArn") or "arn:aws:iam::aws:policy/AdministratorAccess")
        user = world["users"].get(user_name) or _ensure_user(world, user_name)
        policy_name = policy_arn.rsplit("/", 1)[-1]
        if policy_name not in user["policies"]:
            user["policies"].append(policy_name)
        return _iam_xml("AttachUserPolicyResponse", "<AttachUserPolicyResult></AttachUserPolicyResult>")

    if service == "s3" and action in {"listbuckets", ""}:
        buckets = "".join(
            f"<Bucket><Name>{name}</Name><CreationDate>{bucket['created']}</CreationDate></Bucket>"
            for name, bucket in world["buckets"].items()
        )
        return (
            "<ListAllMyBucketsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
            f"<Owner><ID>canonical-user-id</ID><DisplayName>{world['caller']}</DisplayName></Owner>"
            f"<Buckets>{buckets}</Buckets></ListAllMyBucketsResult>"
        )

    if service == "s3" and action in {"listobjects", "listobjects-v2", "listobjectsv2"}:
        bucket_name = str(body.get("Bucket") or next(iter(world["buckets"])))
        bucket = world["buckets"].get(bucket_name)
        if not bucket:
            return None
        contents = "".join(
            "<Contents>"
            f"<Key>{obj['key']}</Key><LastModified>{obj['last_modified']}</LastModified>"
            f"<Size>{obj['size']}</Size><StorageClass>STANDARD</StorageClass>"
            "</Contents>"
            for obj in bucket["objects"]
        )
        return f"<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>{bucket_name}</Name>{contents}<IsTruncated>false</IsTruncated></ListBucketResult>"

    if service == "secretsmanager" and action == "listsecrets":
        return json.dumps({"SecretList": [_secret_summary(secret) for secret in world["secrets"].values()]}, separators=(",", ":"))

    if service == "secretsmanager" and action == "getsecretvalue":
        secret_id = str(_body_value(body, "SecretId") or "prod/db/master")
        secret = _find_secret(world, secret_id)
        if not secret:
            return None
        return json.dumps(
            {
                "ARN": secret["arn"],
                "Name": _secret_name(world, secret),
                "VersionId": "00000000-0000-0000-0000-000000000001",
                "SecretString": secret["value"],
                "VersionStages": ["AWSCURRENT"],
                "CreatedDate": secret["last_changed"],
            },
            separators=(",", ":"),
        )

    if service == "ssm" and action == "describeinstanceinformation":
        return json.dumps({"InstanceInformationList": world["instances"]}, separators=(",", ":"))

    if service == "ssm" and action in {"getparameter", "getparameters"}:
        name = str(_body_value(body, "Name") or "/prod/db/password")
        param = world["parameters"].get(name)
        if not param:
            return None
        return json.dumps(
            {
                "Parameter": {
                    "Name": param["name"],
                    "Type": param["type"],
                    "Value": param["value"],
                    "Version": param["version"],
                    "LastModifiedDate": param["last_modified"],
                    "ARN": f"arn:aws:ssm:{world['region']}:{world['account_id']}:parameter{param['name']}",
                }
            },
            separators=(",", ":"),
        )

    return None


def _normalize_action(action: str) -> str:
    return "".join(ch for ch in action.lower() if ch.isalnum())


def _body_value(body: dict[str, Any], key: str) -> Any:
    if key in body:
        return body[key]
    normalized = _normalize_action(key)
    for candidate_key, value in body.items():
        if _normalize_action(str(candidate_key)) == normalized:
            return value
    return None


def _iam_xml(root: str, inner: str) -> str:
    return _xml(root, inner, "https://iam.amazonaws.com/doc/2010-05-08/")


def _xml(root: str, inner: str, xmlns: str) -> str:
    return f"<{root} xmlns=\"{xmlns}\">{inner}<ResponseMetadata><RequestId>00000000-0000-0000-0000-000000000000</RequestId></ResponseMetadata></{root}>"


def _iam_user_member(user: dict[str, Any]) -> str:
    return f"<member>{_iam_user_fields(user)}</member>"


def _iam_user_fields(user: dict[str, Any]) -> str:
    return (
        f"<Path>{user['path']}</Path><UserName>{user['name']}</UserName>"
        f"<UserId>{user['id']}</UserId><Arn>{user['arn']}</Arn>"
        f"<CreateDate>{user['created']}</CreateDate>"
    )


def _ensure_user(world: dict[str, Any], user_name: str) -> dict[str, Any]:
    if user_name not in world["users"]:
        user_id = f"AIDA{''.join(ch for ch in user_name.upper() if ch.isalnum())[:12]:0<12}"
        world["users"][user_name] = {
            "name": user_name,
            "id": user_id,
            "arn": f"arn:aws:iam::{world['account_id']}:user/{user_name}",
            "path": "/",
            "created": "2024-03-05T12:00:00Z",
            "policies": [],
            "access_keys": [],
        }
    return world["users"][user_name]


def _secret_summary(secret: dict[str, Any]) -> dict[str, Any]:
    return {
        "ARN": secret["arn"],
        "Name": secret["arn"].split(":secret:", 1)[1].rsplit("-", 1)[0],
        "Description": secret["description"],
        "LastChangedDate": secret["last_changed"],
    }


def _find_secret(world: dict[str, Any], secret_id: str) -> dict[str, Any] | None:
    if secret_id in world["secrets"]:
        return world["secrets"][secret_id]
    for secret in world["secrets"].values():
        if secret_id == secret["arn"] or secret_id in secret["arn"]:
            return secret
    return None


def _secret_name(world: dict[str, Any], secret: dict[str, Any]) -> str:
    for name, candidate in world["secrets"].items():
        if candidate is secret:
            return name
    return secret["arn"].split(":secret:", 1)[1].rsplit("-", 1)[0]
