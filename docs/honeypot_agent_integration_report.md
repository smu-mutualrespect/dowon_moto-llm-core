# Honeypot Agent Integration Report

## 1. 목적

이번 통합의 목표는 단순히 `ttuurrnn` 코드 일부를 `dowon` 코드에 붙이는 것이 아니라, 두 구조의 장점을 분리해서 합치는 것이었다.

- `dowon`의 장점: 다중 agent 구조가 명확하다. `analyst`, `generator`, `strategy`가 역할을 나누고, LLM analyst가 다음 행동을 예측해 pre-generation을 수행한다.
- `ttuurrnn`의 장점: 공격자에게 보이는 응답 경로가 빠르다. `state -> template -> cache -> generic -> LLM` 순서로 처리해서 대부분의 AWS CLI 요청을 LLM 없이 빠르게 응답할 수 있다.

따라서 최종 방향은 다음과 같다.

```text
공격자 AWS CLI 요청
  -> Moto native 처리 가능하면 우선 처리
  -> native 응답이 너무 빈약하거나 미구현이면 turn_agent로 진입
  -> turn_agent가 세션 상태와 요청을 정리
  -> response_router가 빠른 응답 경로 선택
       1. state
       2. template
       3. cache
       4. generic
       5. LLM generator
  -> 동시에 백그라운드에서 analyst / strategy agent 실행
```

핵심은 응답 생성과 분석을 분리한 것이다. 공격자에게는 최대한 빠르게 응답하고, 무거운 분석과 전략 수립은 뒤에서 수행한다.

## 2. turn_agent에서 활용한 부분

`turn_agent`는 이번 구조에서 오케스트레이터 역할을 한다.

파일 위치:

- `moto/core/llm_agents/turn_agent.py`

활용한 핵심 흐름은 다음과 같다.

### 2.1 요청 파싱

```python
parsed_service, parsed_action, parsed_body = parse_request(url, headers, body)
service = service or parsed_service
action = action or parsed_action
```

AWS CLI 요청은 서비스와 action이 항상 같은 방식으로 들어오지 않는다. 어떤 서비스는 query string, 어떤 서비스는 `x-amz-target`, 어떤 서비스는 URL path에서 action이 결정된다.

그래서 `turn_agent`는 먼저 요청을 표준화한다.

```text
원본 HTTP 요청
  -> service
  -> action
  -> parsed_body
```

이렇게 표준화해야 뒤의 `state`, `template`, `cache`, `generic`, `LLM`이 같은 입력 형식을 사용할 수 있다.

### 2.2 세션 상태 구성

```python
history_before = get_history(session_id)
profile = get_profile(session_id)
active_decoys = list_decoys(session_id)
decoy_hit = detect_decoy_hit(session_id, service, action, parsed_body)
```

여기서 세션 기반 판단을 한다.

- 이전에 어떤 명령을 실행했는가
- 현재 공격 단계가 무엇인가
- 공격자 유형이 무엇으로 추정되는가
- 이전에 심어둔 decoy를 다시 사용했는가

그 결과를 `AgentState`로 묶는다.

```python
state: AgentState = {
    "session_id": session_id,
    "service": service,
    "action": action,
    "body": parsed_body,
    "history": history_before,
    "turn_count": len(history_before) + 1,
    "attack_stage": profile["attack_stage"],
    "attacker_type": profile["attacker_type"],
    "decoy_placed": bool(active_decoys),
    "decoy_hit": decoy_hit,
    "content_type": content_type,
    "active_decoys": active_decoys,
}
```

이 부분이 중요한 이유는, 단순 LLM 호출이 아니라 “세션을 가진 허니팟”으로 동작하기 위해서다.

예를 들어 공격자가 처음에는 `iam list-users`를 하고, 이후 `iam list-access-keys --user-name prod-audit`를 입력하면, 시스템은 이것을 별개의 두 명령이 아니라 하나의 공격 흐름으로 볼 수 있다.

### 2.3 빠른 응답 라우팅

```python
resp_body, response_source = route_response(...)
```

`turn_agent`가 직접 응답을 생성하지 않고, `response_router`로 넘긴다.

파일 위치:

- `moto/core/llm_agents/response_router.py`

현재 라우팅 순서는 다음과 같다.

```text
state -> template -> cache -> generic -> LLM -> fallback
```

각 단계의 의미는 다음과 같다.

| 단계 | 의미 | 장점 | 한계 |
|---|---|---|---|
| state | fake AWS state에 있는 자원 기반 응답 | 세션 일관성 좋음 | state에 없는 API는 처리 못함 |
| template | 자주 쓰거나 품질이 중요한 API를 직접 작성 | 빠르고 품질 안정적 | 지원 API를 직접 늘려야 함 |
| cache | 이전 생성 응답 재사용 | 반복 요청 빠름 | cache key가 부정확하면 틀린 응답 재사용 위험 |
| generic | botocore schema 기반 응답 생성 | 모르는 JSON API도 빠르게 처리 | 값의 의미 품질은 낮을 수 있음 |
| LLM | schema와 request body를 보고 생성 | 유연하고 자연스러움 | 느리고 비용 발생 |

이 구조를 붙인 이유는 명확하다.

허니팟에서는 응답 속도가 너무 느리면 공격자가 이상함을 느낄 수 있다. 실제 AWS CLI 요청이 매번 5초에서 10초씩 걸리면, 공격자 입장에서는 “이거 진짜 AWS가 아닌데?”라는 의심이 생길 수 있다. 그래서 LLM은 마지막 보강 수단으로 두고, 대부분은 빠른 deterministic path로 처리하도록 했다.

### 2.4 history 저장

```python
history_after = append_history(session_id, service, action)
```

응답을 만든 뒤에는 현재 명령을 세션 history에 기록한다.

이 history는 다음 두 곳에서 사용된다.

- 규칙 기반 analyst
- LLM analyst / strategy agent

즉, 명령어와 답변 전체를 무작정 저장하는 방식이 아니라, 최소한의 흐름 정보인 `service:action`을 저장해 공격 단계를 추정한다.

예:

```text
sts:GetCallerIdentity
iam:ListUsers
iam:ListAccessKeys
secretsmanager:ListSecrets
```

이런 흐름이면 credential access 또는 privilege escalation 가능성이 높다고 판단할 수 있다.

### 2.5 백그라운드 agent 실행

```python
_schedule_background_jobs(session_id, history_after, parsed_body, state, schema)
```

여기서 `turn_agent`가 진짜 agent orchestrator처럼 동작한다.

현재 구조는 다음과 같다.

```text
동기 경로:
  request -> route_response -> 즉시 응답

비동기 경로:
  rule analyst
  LLM analyst
  pre-generation
  strategy agent
  decoy 적용
```

이 부분이 중요한 이유는 응답 속도와 agent 기능을 동시에 챙기기 위해서다.

## 3. ttuurrnn_moto-llm-core에서 가져온 기능

이번 통합에서 가져온 것은 `turn_agent.py` 한 파일이 아니라, `ttuurrnn_moto-llm-core`가 갖고 있던 빠른 응답 처리 구조다.

정확히 말하면 다음 기능들을 가져와 dowon 구조에 붙였다.

```text
1. response_router fast path
2. state_renderer
3. template renderer
4. response cache
5. generic renderer
6. weak native response intercept
7. S3 native intercept
8. request-specific template 보강
```

아래는 각 기능의 의미와 붙인 이유다.

### 3.1 response_router fast path

ttuurrnn에서 가장 중요한 기능은 `response_router`의 빠른 라우팅 구조다.

원래 LLM 기반 허니팟은 요청이 들어올 때마다 LLM이 응답을 생성하면 품질은 좋아질 수 있지만 지연 시간이 길어진다. 그래서 ttuurrnn은 응답 경로를 다음과 같이 나눴다.

```text
state -> template -> cache -> generic -> LLM
```

이 기능을 dowon에 붙인 이유는 다음과 같다.

- 공격자에게 보이는 응답 속도를 낮추기 위해
- LLM 호출 비용을 줄이기 위해
- 이미 잘 아는 AWS API는 deterministic하게 처리하기 위해
- LLM은 정말 필요한 경우에만 쓰기 위해

통합 후 dowon의 `response_router.py`도 이 순서를 따른다.

```python
rendered = render_state_response(state, schema)
templated = render_template_response(state, schema)
draft = get_cached_response(state, schema)
generic = render_generic_response(state, schema)
generated = generate_agent(...)
```

이 구조 덕분에 `ecr`, `iam`, `sts`, `secretsmanager` 일부 명령은 LLM 없이도 빠르게 응답할 수 있다.

### 3.2 state_renderer

`state_renderer`는 fake AWS state에 이미 존재하는 자원을 기반으로 응답을 만드는 기능이다.

예를 들어 fake state에 다음 정보가 있다고 하자.

```text
EC2 instance: i-0abc1234def567890
SSM managed instance: prod-bastion-01
Secret: prod/db/master
IAM user: prod-audit
```

그러면 `ssm describe-instance-information` 같은 요청에 대해 매번 LLM을 부르지 않고, fake state에 있는 정보를 바탕으로 응답한다.

이 기능의 장점은 세션 일관성이다.

```text
한 번 보여준 자원
  -> 다음 요청에서도 같은 이름 / ARN / ID로 등장
```

허니팟에서는 이 일관성이 중요하다. 공격자가 `prod-bastion-01`을 봤는데 다음 응답에서 갑자기 다른 이름이 나오면 가짜 티가 날 수 있다.

### 3.3 template renderer

`template renderer`는 자주 쓰거나 품질이 중요한 API를 직접 작성한 응답으로 처리하는 기능이다.

가져온 이유는 명확하다.

generic renderer는 필드 구조는 맞출 수 있지만, 값의 의미를 항상 정확히 맞추지는 못한다.

예를 들어 ECR에서 generic 응답만 쓰면 이런 문제가 생길 수 있다.

```json
{
  "layerDigest": "prod-batch-check-layer-availability-01",
  "layerAvailability": "prod-batch-check-layer-availability-01",
  "failures": [...]
}
```

문제점:

- `layerDigest`가 `sha256:<64 hex>` 형식이 아니다.
- `layerAvailability`가 `AVAILABLE` 같은 실제 enum 값이 아니다.
- 정상 요청인데 `failures`가 들어간다.

그래서 다음 API는 template으로 승격했다.

```text
ecr batch-check-layer-availability
ecr get-download-url-for-layer
ecr initiate-layer-upload
ecr complete-layer-upload
secretsmanager validate-resource-policy
iam get-context-keys-for-principal-policy
iam list-service-specific-credentials
iam generate-service-last-accessed-details
sts decode-authorization-message
```

template은 LLM보다 빠르고, generic보다 품질이 안정적이다.

### 3.4 response cache

`response_cache`는 이미 생성한 응답을 다시 사용하는 기능이다.

이 기능을 가져온 이유는 반복 요청 대응 때문이다.

공격자는 같은 명령을 여러 번 실행할 수 있다.

```text
aws apprunner list-services
aws apprunner list-services
aws proton list-environments
aws proton list-environments
```

처음 요청에서 응답을 만들고, 이후 같은 맥락의 요청은 cache에서 바로 반환하면 응답 속도가 크게 줄어든다.

다만 ttuurrnn의 기존 cache는 넓게 잡혀 있어서, 요청 파라미터가 다른데 같은 응답이 재사용될 위험이 있었다.

그래서 통합하면서 cache key를 보강했다.

```text
기존:
  service + action + protocol + stage + attacker_type + decoy

보강:
  기존 요소 + request_scope
```

`request_scope`에는 다음 같은 요청값을 포함한다.

```text
repositoryName
layerDigest
layerDigests
uploadId
UserName
SecretId
ResourcePolicy
Bucket
Arn
```

즉, 속도는 유지하되 잘못된 응답 재사용 가능성을 줄였다.

### 3.5 generic renderer

`generic_renderer`는 botocore service model의 output schema를 보고 빠르게 JSON 응답을 만드는 기능이다.

예를 들어 AWS API의 output shape가 다음과 같다면:

```text
ListFlows -> {
  flows: [FlowDefinition],
  nextToken: string
}
```

generic renderer는 이 구조를 보고 LLM 없이 대략적인 응답을 만든다.

장점:

- 모르는 JSON API도 빠르게 처리 가능
- rare AWS service 대응에 좋음
- LLM fallback 호출을 크게 줄임

한계:

- 필드명과 타입은 맞출 수 있지만, 값의 의미는 틀릴 수 있음
- XML/query 계열 API에는 위험해서 적용하지 않는 것이 좋음

그래서 generic은 다음 위치에 둔다.

```text
state -> template -> cache -> generic -> LLM
```

즉, 더 정확한 방법이 없을 때만 generic을 사용한다.

### 3.6 weak native response intercept

Moto 기본 응답이 너무 비어 있거나 simulator 티가 나는 경우가 있다.

예:

```json
{
  "Users": []
}
```

또는:

```text
NoSuchEntity
NoSuchBucket
default_user
arn:aws:sts::123456789012:user/moto
AKIAIOSFODNN7EXAMPLE
Internal Server Error
```

이런 응답은 허니팟 관점에서 위험하다. 공격자가 “실제 AWS 환경이 아니라 빈 mock 서버”라고 의심할 수 있다.

ttuurrnn 구조에서는 이런 약한 native response를 감지해서 `turn_agent`로 넘기는 방식을 썼다.

통합 후 dowon의 `responses.py`에는 다음 역할이 들어갔다.

```text
Moto native response 생성
  -> 응답이 충분히 그럴듯하면 그대로 반환
  -> 응답이 빈약하거나 오류 marker가 있으면 turn_agent fallback
```

이 기능 덕분에 Moto가 빈 배열을 반환하는 상황에서도 허니팟용 fake resource를 보여줄 수 있다.

### 3.7 S3 native intercept

S3는 공격자가 자주 확인하는 서비스다.

```bash
aws s3api list-buckets
aws s3api list-objects-v2 --bucket ...
```

Moto 기본 상태가 비어 있으면 `Buckets: []`가 나오고, 이것도 허니팟 티가 난다.

그래서 ttuurrnn의 방식처럼 S3 일부 응답은 native Moto 결과 전에 intercept해서 `turn_agent` 경로로 보낸다.

그 결과 `list-buckets`에서 다음과 같은 그럴듯한 bucket을 보여줄 수 있다.

```text
prod-config-backups-123456789012
billing-exports-prod
security-audit-logs-use1
```

이 기능은 공격자에게 탐색할 대상을 제공한다는 점에서 중요하다.

### 3.8 request-specific template 보강

ttuurrnn 구조의 장점은 단순히 template을 쓰는 것이 아니라, 요청 body를 반영하려고 한 점이다.

이번 통합에서도 그 방식을 확장했다.

예:

```bash
aws ecr complete-layer-upload \
  --repository-name other-repo \
  --upload-id upload-xyz \
  --layer-digests sha256:bbbb...
```

응답:

```json
{
  "registryId": "123456789012",
  "repositoryName": "other-repo",
  "uploadId": "upload-xyz",
  "layerDigest": "sha256:bbbb..."
}
```

이렇게 해야 공격자가 봤을 때 “내가 입력한 값이 실제 API 처리 결과에 반영됐다”고 느낀다.

허니팟에서는 이 부분이 중요하다. 응답이 빠르기만 하고 요청값을 무시하면 기만 품질이 떨어진다.

### 3.9 ttuurrnn에서 가져왔지만 완전히 가져오지 않은 기능

ttuurrnn에는 다음 기능도 있었다.

```text
deception_metrics
promotion_analyzer
SLM refiner
```

이 기능들은 유용하지만 이번 통합에서는 전부 완전히 붙이지 않았다.

이유:

- 먼저 dowon 최신 코드와 fast response 구조를 안정적으로 합치는 것이 우선이었다.
- metrics/refiner까지 한 번에 붙이면 변경 범위가 커진다.
- 특히 refiner는 cache를 수정할 수 있으므로 응답 일관성 검증이 먼저 필요하다.

다음 단계에서 붙이면 좋은 기능은 다음이다.

```text
1. deception_metrics
   - 응답 안에 decoy가 얼마나 자연스럽게 들어갔는지 기록

2. promotion_analyzer
   - generic/LLM이 자주 처리하는 API를 template 후보로 추천

3. SLM refiner
   - generic 응답을 백그라운드에서 더 자연스럽게 다듬음
```

즉, 이번 통합은 ttuurrnn의 “운영 속도 구조”를 먼저 붙인 것이고, “품질 자동 개선 루프”는 다음 단계로 남겨둔 상태다.

## 4. dowon 구조에 붙인 방식

### 3.1 기존 dowon 구조

dowon 구조는 agent 역할 분리가 명확했다.

```text
analyst agent
  -> 공격 단계 / 의도 / 다음 행동 예측

generator agent
  -> AWS 응답 생성

strategy agent
  -> 어떤 decoy를 심을지 결정
```

하지만 문제는 응답 경로에서 LLM 의존도가 높으면 속도가 느려진다는 점이었다.

기존 측정에서 LLM 기반 생성은 수 초 단위가 나왔다. 허니팟에서는 이 지연이 공격자에게 노출될 수 있다.

### 3.2 붙인 구조

dowon의 agent 구조는 유지하되, 공격자에게 보이는 응답 앞단에 빠른 라우터를 붙였다.

```text
dowon agent 구조
  analyst / generator / strategy

추가한 빠른 응답 구조
  state / template / cache / generic
```

즉, dowon의 “생각하는 두뇌”는 유지하고, ttuurrnn의 “빠른 응답 처리부”를 앞단에 붙인 것이다.

최종 구조는 다음과 같다.

```text
AWS CLI 요청
  -> Moto
  -> weak native response 또는 미구현 API 감지
  -> turn_agent.run()
       -> request_parser
       -> schema loader
       -> session/profile/decoy state 구성
       -> response_router
            -> state
            -> template
            -> cache
            -> generic
            -> generator LLM
       -> append_history
       -> background analyst / strategy / pre-generation
```

## 5. 이번 통합에서 실제로 바꾼 부분

### 4.1 LLM analyst 실행 빈도 조정

파일:

- `moto/core/llm_agents/turn_agent.py`

변경:

```python
if len(history) % _BACKGROUND_AFTER_TURNS == 0:
    worker = threading.Thread(...)
    worker.start()
```

의미:

- LLM analyst를 매 요청마다 돌리지 않는다.
- 기본값은 5턴마다 실행한다.
- 공격자 응답 속도에 영향을 줄 가능성을 줄인다.

왜 필요한가:

- LLM analyst는 공격 의도 분석에는 좋지만 매번 호출하면 지연과 비용이 커진다.
- 허니팟에서는 “생각을 많이 하는 것”보다 “티 안 나게 빠르게 반응하는 것”이 더 중요할 때가 많다.

### 4.2 strategy agent 실행 조건 조정

파일:

- `moto/core/llm_agents/turn_agent.py`

변경:

```python
stage_changed = profile["attack_stage"] != base_state["attack_stage"]
if (len(history) == 1 or stage_changed) and mark_strategy_inflight(session_id):
    strat_worker = threading.Thread(...)
```

의미:

- 첫 턴 또는 공격 단계가 바뀔 때 strategy를 실행한다.
- 같은 세션에서 strategy가 중복 실행되지 않도록 `mark_strategy_inflight()`로 막는다.

왜 필요한가:

- decoy 전략은 매 요청마다 새로 만들 필요가 없다.
- 너무 자주 바뀌면 오히려 세션 일관성이 깨질 수 있다.

### 4.3 cache key 개선

파일:

- `moto/core/llm_agents/response_cache.py`

기존 문제:

캐시가 `service/action/stage/decoy` 중심이면 다음 문제가 생긴다.

```text
complete-layer-upload repository=demo
complete-layer-upload repository=other-repo
```

두 요청이 같은 캐시를 공유하면 `other-repo` 요청에 `demo` 응답이 나갈 수 있다.

변경:

```python
"request_scope": _request_scope(state)
```

`_request_scope()`는 다음과 같은 핵심 요청값을 cache key에 포함한다.

- `repositoryName`
- `layerDigest`
- `layerDigests`
- `uploadId`
- `UserName`
- `SecretId`
- `ResourcePolicy`
- `Bucket`
- `Arn`

왜 필요한가:

- 속도 때문에 캐시를 쓰되, 요청 파라미터가 다른데 같은 응답이 나가는 문제를 줄이기 위해서다.

### 4.4 ECR 응답 품질 개선

파일:

- `moto/core/llm_agents/templates.py`

추가한 template:

- `ecr batch-check-layer-availability`
- `ecr get-download-url-for-layer`
- `ecr initiate-layer-upload`
- `ecr complete-layer-upload`

기존 generic 응답의 문제:

```json
{
  "layerDigest": "prod-batch-check-layer-availability-01",
  "layerAvailability": "prod-batch-check-layer-availability-01",
  "failures": [...]
}
```

문제점:

- `layerDigest`가 SHA256 형식이 아니다.
- `layerAvailability`가 AWS enum 값이 아니다.
- 정상 입력인데 `failures`가 채워진다.

변경 후:

```json
{
  "layers": [
    {
      "layerDigest": "sha256:aaaaaaaa...",
      "layerAvailability": "AVAILABLE",
      "layerSize": 7340032,
      "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip"
    }
  ],
  "failures": []
}
```

즉, 응답 구조뿐 아니라 값의 의미도 AWS스럽게 맞췄다.

### 4.5 SecretsManager 정책 검증 품질 개선

파일:

- `moto/core/llm_agents/templates.py`

대상:

- `secretsmanager validate-resource-policy`

변경:

```python
broad = _looks_like_broad_secret_policy(policy)
```

정책에 다음과 같은 broad access가 있으면 실패로 응답한다.

```json
{
  "Effect": "Allow",
  "Principal": "*",
  "Action": "secretsmanager:GetSecretValue",
  "Resource": "*"
}
```

변경 후 응답:

```json
{
  "PolicyValidationPassed": false,
  "ValidationErrors": [
    {
      "CheckName": "BroadAccessCheck",
      "ErrorMessage": "Resource policy grants access to a broad principal."
    }
  ]
}
```

왜 필요한가:

- 이전 generic 응답은 필드명만 맞고 에러 메시지가 부자연스러웠다.
- 보안 관련 API는 값의 의미가 중요하므로 template으로 승격했다.

## 6. 테스트 결과

테스트한 명령어:

```text
ssm describe-instance-information
ecr batch-check-layer-availability
ecr get-download-url-for-layer
ecr initiate-layer-upload
ecr complete-layer-upload
iam get-context-keys-for-principal-policy
iam list-service-specific-credentials
iam generate-service-last-accessed-details
secretsmanager validate-resource-policy
sts decode-authorization-message
```

결과:

```text
round 1 평균: 639.9ms, 성공 10/10
round 2 평균: 463.6ms, 성공 10/10
```

route source:

```text
ssm -> state
ecr -> template
iam -> template
secretsmanager validate-resource-policy -> template
sts decode-authorization-message -> template
```

의미:

- 대부분 LLM 없이 처리되었다.
- 공격자에게 보이는 응답 속도는 낮아졌다.
- 동시에 요청값 기반 응답을 만들기 때문에 세션 일관성도 이전 generic보다 좋아졌다.

## 7. 이게 agent라고 할 수 있는가?

결론부터 말하면, “모든 응답을 LLM이 생성하는 agent”라고 말하면 부정확하다. 하지만 “agent-assisted adaptive honeypot” 또는 “multi-agent control plane을 가진 AWS API honeypot”이라고 말하는 것은 타당하다.

### 6.1 agent라고 말할 수 있는 부분

이 프로젝트에는 다음 agent 역할이 있다.

```text
Analyst Agent
  - 세션 history를 보고 공격 단계와 의도를 판단
  - 다음 예상 행동을 예측

Generator Agent
  - schema와 request body 기반으로 AWS 응답 생성
  - 민감값이 포함되면 decoy 등록 tool 호출 가능

Strategy Agent
  - 공격 단계와 프로파일을 보고 어떤 미끼를 심을지 결정

Router
  - 현재 요청을 state/template/cache/generic/LLM 중 어디로 보낼지 결정
```

특히 agent답다고 볼 수 있는 지점은 다음이다.

- 세션 history를 본다.
- 공격 단계와 공격자 유형을 갱신한다.
- decoy hit를 감지한다.
- 다음 행동을 예측한다.
- 예측된 operation을 pre-generation한다.
- strategy agent가 decoy를 만들고 fake state에 반영한다.

즉, 단순히 `LLM + tool`만 있는 구조는 아니다.

### 6.2 agent라고 과장하면 안 되는 부분

다만 다음 표현은 피하는 것이 좋다.

```text
모든 AWS 응답을 AI agent가 자체 판단으로 생성한다.
```

왜냐하면 실제 응답의 많은 부분은 `state`, `template`, `generic` 같은 deterministic path에서 나온다.

더 정확한 표현은 다음이다.

```text
공격자에게 보이는 응답은 빠른 deterministic renderer가 우선 처리하고,
agent들은 백그라운드에서 세션 분석, 미끼 전략 생성, LLM fallback 응답 생성을 담당한다.
```

또는:

```text
응답 data plane과 agent control plane을 분리한 multi-agent honeypot 구조다.
```

### 6.3 발표용 표현

dowon에게 설명할 때는 이렇게 말하면 된다.

```text
기존 dowon 구조는 analyst/generator/strategy agent가 명확해서 연구 구조는 좋았지만,
공격자 요청마다 LLM이 개입하면 응답 시간이 길어지는 문제가 있었다.

그래서 turn_agent는 유지하되, 공격자에게 바로 보이는 응답 경로에는
state/template/cache/generic fast path를 붙였다.

LLM agent는 모든 응답을 직접 만들기보다,
복잡하거나 미지원인 요청을 보강하고,
백그라운드에서 공격 의도 분석, 다음 행동 예측, decoy 전략 생성을 담당하게 했다.

결과적으로 응답 속도는 낮아졌고,
ECR/SecretsManager처럼 generic 품질이 낮던 API는 request_body 기반 template으로 올려
응답의 질과 세션 일관성도 개선했다.
```

## 8. 한계와 다음 보완점

현재 구조도 완성형은 아니다.

### 7.1 한계

- template이 많아질수록 유지보수 비용이 늘어난다.
- generic renderer는 schema field는 맞추지만 값의 의미는 틀릴 수 있다.
- 세션 상태는 아직 인메모리 중심이라 서버 재시작 시 사라진다.
- pre-generation은 현재 예측 operation에 빈 body를 넣는 경우가 있어, request-specific pregen은 아직 제한적이다.

### 7.2 다음 개선 방향

우선순위는 다음과 같다.

1. `fake_state_store`를 더 강한 source of truth로 만들기
2. template/generic이 fake state를 참조하게 하기
3. pre-generation에서 빈 body 대신 decoy나 최근 list 결과를 기반으로 후보 body 만들기
4. generic renderer에 enum/value 규칙 추가하기
5. deception quality metric 자동화하기

## 9. 참고 기준

이 설계는 다음 AWS 동작 기준을 참고해 검증하는 것이 좋다.

- AWS CLI Command Reference: https://docs.aws.amazon.com/cli/latest/reference/
- Botocore service model 개념: https://botocore.amazonaws.com/v1/documentation/api/latest/reference/loaders.html
- AWS IAM API Reference: https://docs.aws.amazon.com/IAM/latest/APIReference/
- Amazon ECR API Reference: https://docs.aws.amazon.com/AmazonECR/latest/APIReference/
- AWS Secrets Manager API Reference: https://docs.aws.amazon.com/secretsmanager/latest/apireference/

보고서에서 중요한 점은 “LLM을 많이 쓴다”가 아니라, “LLM을 필요한 위치에만 쓰고, 허니팟 운영에 중요한 응답 속도와 일관성을 앞단에서 보장한다”는 것이다.
