import os
import re
from io import BytesIO
from typing import Any, Optional, Union

_LOOPBACK_ALIASES = {"localhost", "::1", "0.0.0.0"}


def _resolve_session_id(forwarded_for: str, host: str, remote_addr: str = "") -> str:
    raw = (forwarded_for or remote_addr or host.split(":")[0]).strip()
    if not raw:
        return "unknown"
    return "127.0.0.1" if raw in _LOOPBACK_ALIASES else raw

from botocore.awsrequest import AWSResponse

import moto.backend_index as backend_index
from moto.core.base_backend import BackendDict
from moto.core.common_types import TYPE_RESPONSE
from moto.core.config import passthrough_service, passthrough_url, service_whitelisted
from moto.core.exceptions import ServiceNotWhitelisted
from moto.core.llm_fallback import (
    build_llm_fallback_json,
    call_claude_api,
    call_gpt_api,
)
from moto.core.utils import get_equivalent_url_in_aws_domain


class MockRawResponse(BytesIO):
    def __init__(self, response_input: Union[str, bytes]):
        if isinstance(response_input, str):
            response_input = response_input.encode("utf-8")
        super().__init__(response_input)

    def stream(self, **kwargs: Any) -> Any:
        contents = self.read()
        while contents:
            yield contents
            contents = self.read()


class BotocoreStubber:
    def __init__(self) -> None:
        self.enabled = False

    def __call__(
        self, event_name: str, request: Any, **kwargs: Any
    ) -> Optional[AWSResponse]:
        if not self.enabled:
            return None

        response = self.process_request(request)
        if response is not None:
            status, headers, body = response
            return AWSResponse(request.url, status, headers, MockRawResponse(body))  # type: ignore[arg-type]
        else:
            return response

    def process_request(self, request: Any) -> Optional[TYPE_RESPONSE]:
        # Handle non-standard AWS endpoint hostnames from ISO regions or custom
        # S3 endpoints.
        parsed_url, _ = get_equivalent_url_in_aws_domain(request.url)
        # Remove the querystring from the URL, as we'll never match on that
        clean_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"

        if passthrough_url(clean_url):
            return None

        for service, pattern in backend_index.backend_url_patterns:
            if pattern.match(clean_url):
                if passthrough_service(service):
                    return None

                if not service_whitelisted(service):
                    raise ServiceNotWhitelisted(service)

                from moto.core.llm_agents.intercept import should_intercept_native
                if should_intercept_native(service):
                    from moto.core.llm_agents import turn_agent

                    source = _resolve_session_id(
                        request.headers.get("X-Forwarded-For", ""),
                        request.headers.get("Host", ""),
                        getattr(request, "remote_addr", ""),
                    )
                    resp_headers, resp_body = turn_agent.run(
                        url=request.url,
                        headers=dict(request.headers),
                        body=getattr(request, "body", None),
                        source=source,
                        service=service,
                        method=getattr(request, "method", None),
                    )
                    return 200, resp_headers, resp_body

                import moto.backends as backends
                from moto.core import DEFAULT_ACCOUNT_ID
                from moto.core.exceptions import HTTPException

                # TODO: cache this part - we only need backend.urls
                backend_dict = backends.get_backend(service)  # type: ignore[call-overload]

                if isinstance(backend_dict, BackendDict):
                    if "us-east-1" in backend_dict[DEFAULT_ACCOUNT_ID]:
                        backend = backend_dict[DEFAULT_ACCOUNT_ID]["us-east-1"]
                    else:
                        backend = backend_dict[DEFAULT_ACCOUNT_ID]["aws"]
                else:
                    backend = backend_dict["global"]

                for header, value in request.headers.items():
                    if isinstance(value, bytes):
                        request.headers[header] = value.decode("utf-8")

                for url, method_to_execute in backend.urls.items():
                    if re.compile(url).match(clean_url):
                        from moto.moto_api import recorder

                        try:
                            recorder._record_request(request)
                            status, headers, body = method_to_execute(
                                request, request.url, request.headers
                            )
                        except HTTPException as e:
                            status = e.code
                            headers = e.get_headers()
                            body = e.get_body()

                        return status, headers, body

        if re.compile(r"https?://.+\.amazonaws\.com(/.*)?$").match(clean_url):
            # AWS URL은 맞지만 moto backend URL 매칭이 없을 때 turn_agent로 넘긴다.
            # turn_agent가 세션 추적, 공격 단계 추론, 응답 생성을 모두 처리한다.
            from moto.core.llm_agents import turn_agent

            source = request.headers.get("X-Forwarded-For") or request.headers.get("Host", "").split(":")[0] or "unknown"
            try:
                resp_headers, resp_body = turn_agent.run(
                    url=request.url,
                    headers=dict(request.headers),
                    body=getattr(request, "body", None),
                    source=source,
                )
                return 200, resp_headers, resp_body
            except Exception:
                # turn_agent 호출이 실패하면 최소 fallback을 반환한다.
                fallback_headers, fallback_body = build_llm_fallback_json()
                return 200, fallback_headers, fallback_body

        return None
