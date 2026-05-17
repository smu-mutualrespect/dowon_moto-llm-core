# 40 Command Honeypot Evaluation Report

## 1. 테스트 조건

- 대상 repo: `dowon_moto-llm-core`
- 테스트 방식: 새 Docker 컨테이너 `dowon-40cmd-test`를 띄워 세션/캐시가 없는 초기 상태에서 40개 명령을 1회씩 실행
- endpoint: `http://127.0.0.1:5019`
- 원본 결과 디렉터리: `/tmp/dowon_40cmd_eval_20260517_194328`
- AWS credential: 테스트용 더미 access key 사용

실행을 위해 아래 placeholder는 더미 값으로 치환했다.

| 원본 placeholder | 테스트 치환값 |
|---|---|
| `<view-arn>` | `arn:aws:resource-explorer-2:us-east-1:123456789012:view/prod-view/11111111-2222-3333-4444-555555555555` |
| `<analyzer-arn>` | `arn:aws:access-analyzer:us-east-1:123456789012:analyzer/prod-analyzer` |
| `<stack-name>` | `prod-core` |

주의: `route_source=llm`이라고 찍힌 항목 중 실제 외부 LLM 호출이 있었던 것은 아니다. 이번 테스트에서 `llm_usage` 로그는 없었다. 일부 query/ec2 API는 generator branch로 들어갔지만 output schema가 비어 있어 즉시 빈 성공 응답을 반환했다.

## 2. 전체 요약

- 총 명령어: 40개
- 성공: 36개
- 실패: 4개
- 평균 응답 시간: 767.5ms
- route source 분포: `generic` 13개, `llm` 11개, `-` 6개, `state` 1개, `template` 9개

주의할 점은 `exit_code=0`이 곧 허니팟 품질 합격을 의미하지 않는다는 것이다. 특히 EC2 계열 일부 명령은 AWS CLI 프로토콜상 성공으로 끝났지만 응답 본문이 비어 있어 공격자 관점에서는 "비어 있는 테스트 계정" 또는 "불완전한 mock"처럼 보일 수 있다. 이런 항목은 속도 측정에서는 성공이지만, 기만 품질 기준에서는 보강 필요로 분리해서 봐야 한다.

실패한 명령은 다음 4개다.

| # | 명령어 | exit_code | 원인 요약 |
|---:|---|---:|---|
| 17 | `cloudformation describe-stack-resources` | 255 | Moto native CloudFormation 상태에 stack이 없어 ValidationError가 반환됨. 허니팟 관점에서는 빈 native state가 드러나는 지점이라 template/state 보강 후보. |
| 19 | `organizations list-roots` | 255 | Moto native Organizations가 organization 미사용 상태를 반환함. 공격자에게는 실제 빈 계정처럼 보일 수 있으나, 허니팟 기만 목적이면 roots template 보강 후보. |
| 27 | `healthomics list-runs` | 2 | 서버 요청 전 AWS CLI 로컬 단계에서 실패. 현재 설치된 AWS CLI에는 `healthomics` command가 없고, 관련 서비스명은 `omics`로 노출됨. |
| 28 | `mgn describe-source-servers` | 255 | turn_agent generic 경로까지 갔지만 응답 shape가 AWS CLI 역직렬화 기대와 맞지 않아 클라이언트 에러 발생. mgn 전용 template 또는 generic renderer 보강 필요. |

## 3. 측정 표

| # | 명령어 | 응답시간(ms) | exit | route_source | route 내부시간(ms) | 품질 판단 |
|---:|---|---:|---:|---|---:|---|
| 1 | `bedrock list-foundation-models` | 3922 | 0 | `generic` | 0.49 | 중간: schema 구조는 맞지만 값 의미는 검토 필요 |
| 2 | `ec2 monitor-instances` | 1990 | 0 | `llm` | 0.3 | 보강 필요: 성공했지만 응답 본문이 비어 있음. EC2 template/generic XML renderer 필요 |
| 3 | `ec2 unmonitor-instances` | 820 | 0 | `llm` | 0.27 | 보강 필요: 성공했지만 응답 본문이 비어 있음. EC2 template/generic XML renderer 필요 |
| 4 | `ec2 describe-reserved-instances` | 696 | 0 | `llm` | 0.24 | 보강 필요: 성공했지만 응답 본문이 비어 있음. EC2 template/generic XML renderer 필요 |
| 5 | `ec2 describe-reserved-instances-listings` | 638 | 0 | `llm` | 0.26 | 보강 필요: 성공했지만 응답 본문이 비어 있음. EC2 template/generic XML renderer 필요 |
| 6 | `ec2 purchase-reserved-instances-offering` | 613 | 0 | `llm` | 0.28 | 보강 필요: 성공했지만 응답 본문이 비어 있음. EC2 template/generic XML renderer 필요 |
| 7 | `ec2 describe-volume-status` | 684 | 0 | `llm` | 0.27 | 보강 필요: 성공했지만 응답 본문이 비어 있음. EC2 template/generic XML renderer 필요 |
| 8 | `ec2 modify-volume-attribute` | 596 | 0 | `llm` | 0.08 | 검토 필요: 이 API는 출력 shape가 없는 계열이라 빈 응답이 자연스러울 수 있음 |
| 9 | `ec2 create-spot-datafeed-subscription` | 623 | 0 | `llm` | 0.19 | 보강 필요: 성공했지만 응답 본문이 비어 있음. EC2 template/generic XML renderer 필요 |
| 10 | `ec2 describe-bundle-tasks` | 687 | 0 | `llm` | 0.32 | 보강 필요: 성공했지만 응답 본문이 비어 있음. EC2 template/generic XML renderer 필요 |
| 11 | `resource-explorer-2 list-indexes` | 520 | 0 | `generic` | 0.22 | 중간: schema 구조는 맞지만 값 의미는 검토 필요 |
| 12 | `resource-explorer-2 list-views` | 458 | 0 | `generic` | 0.1 | 중간: schema 구조는 맞지만 값 의미는 검토 필요 |
| 13 | `resource-explorer-2 search` | 444 | 0 | `generic` | 0.16 | 중간: schema 구조는 맞지만 값 의미는 검토 필요 |
| 14 | `accessanalyzer list-analyzers` | 493 | 0 | `llm` | 0.14 | 주의: route는 llm이나 실제 provider 호출 로그는 없음. 빈/기본 generator 응답 가능성 |
| 15 | `accessanalyzer list-findings` | 441 | 0 | `llm` | 0.15 | 주의: route는 llm이나 실제 provider 호출 로그는 없음. 빈/기본 generator 응답 가능성 |
| 16 | `cloudformation list-stacks` | 1901 | 0 | `-` | - | native Moto 응답: 허니팟 기만성은 별도 검토 필요 |
| 17 | `cloudformation describe-stack-resources` | 463 | 255 | `-` | - | 실패/보강 필요 |
| 18 | `organizations list-accounts` | 475 | 0 | `-` | - | native Moto 응답: 허니팟 기만성은 별도 검토 필요 |
| 19 | `organizations list-roots` | 438 | 255 | `-` | - | 실패/보강 필요 |
| 20 | `backup list-backup-vaults` | 2532 | 0 | `-` | - | native Moto 응답: 허니팟 기만성은 별도 검토 필요 |
| 21 | `billingconductor list-billing-groups` | 612 | 0 | `generic` | 0.22 | 중간: schema 구조는 맞지만 값 의미는 검토 필요 |
| 22 | `frauddetector get-detectors` | 556 | 0 | `generic` | 0.14 | 중간: schema 구조는 맞지만 값 의미는 검토 필요 |
| 23 | `detective list-graphs` | 577 | 0 | `generic` | 0.12 | 중간: schema 구조는 맞지만 값 의미는 검토 필요 |
| 24 | `auditmanager list-assessments` | 534 | 0 | `generic` | 0.24 | 중간: schema 구조는 맞지만 값 의미는 검토 필요 |
| 25 | `outposts list-outposts` | 531 | 0 | `generic` | 0.24 | 중간: schema 구조는 맞지만 값 의미는 검토 필요 |
| 26 | `appflow list-flows` | 546 | 0 | `generic` | 0.19 | 중간: schema 구조는 맞지만 값 의미는 검토 필요 |
| 27 | `healthomics list-runs` | 447 | 2 | `-` | - | 실패/보강 필요 |
| 28 | `mgn describe-source-servers` | 594 | 255 | `generic` | 0.47 | 실패/보강 필요 |
| 29 | `codeguru-reviewer list-repository-associations` | 588 | 0 | `generic` | 0.21 | 중간: schema 구조는 맞지만 값 의미는 검토 필요 |
| 30 | `backup-gateway list-gateways` | 599 | 0 | `generic` | 0.26 | 중간: schema 구조는 맞지만 값 의미는 검토 필요 |
| 31 | `ssm describe-instance-information` | 611 | 0 | `state` | 0.04 | 좋음: fake state 기반, 세션 일관성 우수 |
| 32 | `ecr batch-check-layer-availability` | 550 | 0 | `template` | 0.04 | 좋음: 명시 template, 요청값 반영 가능 |
| 33 | `ecr get-download-url-for-layer` | 581 | 0 | `template` | 0.03 | 좋음: 명시 template, 요청값 반영 가능 |
| 34 | `ecr initiate-layer-upload` | 542 | 0 | `template` | 0.04 | 좋음: 명시 template, 요청값 반영 가능 |
| 35 | `ecr complete-layer-upload` | 542 | 0 | `template` | 0.04 | 좋음: 명시 template, 요청값 반영 가능 |
| 36 | `iam get-context-keys-for-principal-policy` | 671 | 0 | `template` | 0.03 | 좋음: 명시 template, 요청값 반영 가능 |
| 37 | `iam list-service-specific-credentials` | 567 | 0 | `template` | 0.03 | 좋음: 명시 template, 요청값 반영 가능 |
| 38 | `iam generate-service-last-accessed-details` | 521 | 0 | `template` | 0.03 | 좋음: 명시 template, 요청값 반영 가능 |
| 39 | `secretsmanager validate-resource-policy` | 588 | 0 | `template` | 0.04 | 좋음: 명시 template, 요청값 반영 가능 |
| 40 | `sts decode-authorization-message` | 510 | 0 | `template` | 0.04 | 좋음: 명시 template, 요청값 반영 가능 |

## 4. 응답 결과

### 1. bedrock list-foundation-models

- 응답시간: `3922ms`
- exit_code: `0`
- route_source: `generic`
- 판단: 중간: schema 구조는 맞지만 값 의미는 검토 필요

```json
{
    "modelSummaries": [
        {
            "modelArn": "arn:aws:bedrock:us-east-1:123456789012:foundation-model/prod-foundation-model-01",
            "modelId": "bedrock-0a1b2c3d4e5f67890",
            "modelName": "prod-foundation-model-01",
            "providerName": "prod-foundation-model-01",
            "inputModalities": [
                "prod-foundation-model-01"
            ],
            "outputModalities": [
                "prod-foundation-model-01"
            ],
            "responseStreamingSupported": false,
            "customizationsSupported": [
                "prod-foundation-model-01"
            ],
            "inferenceTypesSupported": [
                "FOUNDATION-MODEL"
            ],
            "modelLifecycle": {
                "status": "ACTIVE",
                "startOfLifeTime": 1704067200.0,
                "endOfLifeTime": 1704067200.0,
                "legacyTime": 1704067200.0,
                "publicExtendedAccessTime": 1704067200.0
            }
        }
    ]
}
```

### 2. ec2 monitor-instances

- 응답시간: `1990ms`
- exit_code: `0`
- route_source: `llm`
- 판단: 보강 필요. 성공했지만 응답 본문이 비어 있어 허니팟 기만 품질 기준에서는 부족하다. EC2 template 또는 EC2 XML generic renderer가 필요하다.

```text
(empty response body)
```

### 3. ec2 unmonitor-instances

- 응답시간: `820ms`
- exit_code: `0`
- route_source: `llm`
- 판단: 보강 필요. 성공했지만 응답 본문이 비어 있어 허니팟 기만 품질 기준에서는 부족하다. EC2 template 또는 EC2 XML generic renderer가 필요하다.

```text
(empty response body)
```

### 4. ec2 describe-reserved-instances

- 응답시간: `696ms`
- exit_code: `0`
- route_source: `llm`
- 판단: 보강 필요. 성공했지만 응답 본문이 비어 있어 허니팟 기만 품질 기준에서는 부족하다. EC2 template 또는 EC2 XML generic renderer가 필요하다.

```text
(empty response body)
```

### 5. ec2 describe-reserved-instances-listings

- 응답시간: `638ms`
- exit_code: `0`
- route_source: `llm`
- 판단: 보강 필요. 성공했지만 응답 본문이 비어 있어 허니팟 기만 품질 기준에서는 부족하다. EC2 template 또는 EC2 XML generic renderer가 필요하다.

```text
(empty response body)
```

### 6. ec2 purchase-reserved-instances-offering

- 응답시간: `613ms`
- exit_code: `0`
- route_source: `llm`
- 판단: 보강 필요. 성공했지만 응답 본문이 비어 있어 허니팟 기만 품질 기준에서는 부족하다. EC2 template 또는 EC2 XML generic renderer가 필요하다.

```text
(empty response body)
```

### 7. ec2 describe-volume-status

- 응답시간: `684ms`
- exit_code: `0`
- route_source: `llm`
- 판단: 보강 필요. 성공했지만 응답 본문이 비어 있어 허니팟 기만 품질 기준에서는 부족하다. EC2 template 또는 EC2 XML generic renderer가 필요하다.

```text
(empty response body)
```

### 8. ec2 modify-volume-attribute

- 응답시간: `596ms`
- exit_code: `0`
- route_source: `llm`
- 판단: 검토 필요. 출력 shape가 없는 API 계열이라 빈 응답이 자연스러울 수 있지만, 실제 AWS CLI 표시와 비교해 확인해야 한다.

```text
(empty response body)
```

### 9. ec2 create-spot-datafeed-subscription

- 응답시간: `623ms`
- exit_code: `0`
- route_source: `llm`
- 판단: 보강 필요. 성공했지만 응답 본문이 비어 있어 허니팟 기만 품질 기준에서는 부족하다. EC2 template 또는 EC2 XML generic renderer가 필요하다.

```text
(empty response body)
```

### 10. ec2 describe-bundle-tasks

- 응답시간: `687ms`
- exit_code: `0`
- route_source: `llm`
- 판단: 보강 필요. 성공했지만 응답 본문이 비어 있어 허니팟 기만 품질 기준에서는 부족하다. EC2 template 또는 EC2 XML generic renderer가 필요하다.

```text
(empty response body)
```

### 11. resource-explorer-2 list-indexes

- 응답시간: `520ms`
- exit_code: `0`
- route_source: `generic`
- 판단: 중간: schema 구조는 맞지만 값 의미는 검토 필요

```json
{
    "Indexes": [
        {
            "Region": "prod-indexe-01",
            "Arn": "arn:aws:resource-explorer-2:us-east-1:123456789012:indexe/prod-indexe-01",
            "Type": "INDEXE"
        }
    ]
}
```

### 12. resource-explorer-2 list-views

- 응답시간: `458ms`
- exit_code: `0`
- route_source: `generic`
- 판단: 중간: schema 구조는 맞지만 값 의미는 검토 필요

```json
{
    "Views": [
        "prod-view-01"
    ]
}
```

### 13. resource-explorer-2 search

- 응답시간: `444ms`
- exit_code: `0`
- route_source: `generic`
- 판단: 중간: schema 구조는 맞지만 값 의미는 검토 필요

```json
{
    "Resources": [
        {
            "Arn": "arn:aws:resource-explorer-2:us-east-1:123456789012:search/prod-search-01",
            "OwningAccountId": "resource-0a1b2c3d4e5f67890",
            "Region": "prod-search-01",
            "ResourceType": "SEARCH",
            "Service": "prod-search-01",
            "LastReportedAt": 1704067200.0,
            "Properties": [
                {
                    "Name": "prod-search-01",
                    "LastReportedAt": "prod-search-01",
                    "Data": "prod-search-01"
                }
            ]
        }
    ],
    "ViewArn": "arn:aws:resource-explorer-2:us-east-1:123456789012:search/prod-search-01",
    "Count": {
        "TotalResources": 1,
        "Complete": false
    }
}
```

### 14. accessanalyzer list-analyzers

- 응답시간: `493ms`
- exit_code: `0`
- route_source: `llm`
- 판단: 주의: route는 llm이나 실제 provider 호출 로그는 없음. 빈/기본 generator 응답 가능성

```text
(empty response body)
```

### 15. accessanalyzer list-findings

- 응답시간: `441ms`
- exit_code: `0`
- route_source: `llm`
- 판단: 주의: route는 llm이나 실제 provider 호출 로그는 없음. 빈/기본 generator 응답 가능성

```text
(empty response body)
```

### 16. cloudformation list-stacks

- 응답시간: `1901ms`
- exit_code: `0`
- route_source: `-`
- 판단: native Moto 응답: 허니팟 기만성은 별도 검토 필요

```json
{
    "StackSummaries": []
}
```

### 17. cloudformation describe-stack-resources

- 응답시간: `463ms`
- exit_code: `255`
- route_source: `-`
- 판단: 실패/보강 필요
- 특이사항: Moto native CloudFormation 상태에 stack이 없어 ValidationError가 반환됨. 허니팟 관점에서는 빈 native state가 드러나는 지점이라 template/state 보강 후보.

```text
An error occurred (ValidationError) when calling the DescribeStackResources operation: Stack with id prod-core does not exist
```

### 18. organizations list-accounts

- 응답시간: `475ms`
- exit_code: `0`
- route_source: `-`
- 판단: native Moto 응답: 허니팟 기만성은 별도 검토 필요

```json
{
    "Accounts": []
}
```

### 19. organizations list-roots

- 응답시간: `438ms`
- exit_code: `255`
- route_source: `-`
- 판단: 실패/보강 필요
- 특이사항: Moto native Organizations가 organization 미사용 상태를 반환함. 공격자에게는 실제 빈 계정처럼 보일 수 있으나, 허니팟 기만 목적이면 roots template 보강 후보.

```text
An error occurred (AWSOrganizationsNotInUseException) when calling the ListRoots operation: Your account is not a member of an organization.
```

### 20. backup list-backup-vaults

- 응답시간: `2532ms`
- exit_code: `0`
- route_source: `-`
- 판단: native Moto 응답: 허니팟 기만성은 별도 검토 필요

```json
{
    "BackupVaultList": []
}
```

### 21. billingconductor list-billing-groups

- 응답시간: `612ms`
- exit_code: `0`
- route_source: `generic`
- 판단: 중간: schema 구조는 맞지만 값 의미는 검토 필요

```json
{
    "BillingGroups": [
        {
            "Name": "prod-billing-group-01",
            "Arn": "arn:aws:billingconductor:us-east-1:123456789012:billing-group/prod-billing-group-01",
            "Description": "Production billing-group resource",
            "PrimaryAccountId": "billingc-0a1b2c3d4e5f67890",
            "ComputationPreference": {
                "PricingPlanArn": "arn:aws:billingconductor::123456789012:pricingplan/prod-pricing-plan"
            },
            "Size": 2,
            "CreationTime": 1704067200,
            "LastModifiedTime": 1704067200,
            "Status": "ACTIVE",
            "StatusReason": "ACTIVE",
            "AccountGrouping": {
                "AutoAssociate": false,
                "ResponsibilityTransferArn": "arn:aws:billingconductor:us-east-1:123456789012:billing-group/prod-billing-group-01"
            },
            "BillingGroupType": "PRIMARY"
        }
    ]
}
```

### 22. frauddetector get-detectors

- 응답시간: `556ms`
- exit_code: `0`
- route_source: `generic`
- 판단: 중간: schema 구조는 맞지만 값 의미는 검토 필요

```json
{
    "detectors": [
        {
            "detectorId": "frauddet-0a1b2c3d4e5f67890",
            "description": "Production detector resource",
            "eventTypeName": "DETECTOR",
            "lastUpdatedTime": "2024-01-01T00:00:00Z",
            "createdTime": "2024-01-01T00:00:00Z",
            "arn": "arn:aws:frauddetector:us-east-1:123456789012:detector/prod-detector-01"
        }
    ],
    "nextToken": ""
}
```

### 23. detective list-graphs

- 응답시간: `577ms`
- exit_code: `0`
- route_source: `generic`
- 판단: 중간: schema 구조는 맞지만 값 의미는 검토 필요

```json
{
    "GraphList": [
        {
            "Arn": "arn:aws:detective:us-east-1:123456789012:graph/prod-graph-01",
            "CreatedTime": 1704067200.0
        }
    ],
    "NextToken": ""
}
```

### 24. auditmanager list-assessments

- 응답시간: `534ms`
- exit_code: `0`
- route_source: `generic`
- 판단: 중간: schema 구조는 맞지만 값 의미는 검토 필요

```json
{
    "assessmentMetadata": [
        {
            "name": "prod-assessment-01",
            "id": "auditman-0a1b2c3d4e5f67890",
            "complianceType": "ASSESSMENT",
            "status": "ACTIVE",
            "roles": [
                {
                    "roleType": "ASSESSMENT",
                    "roleArn": "arn:aws:auditmanager:us-east-1:123456789012:assessment/prod-assessment-01"
                }
            ],
            "delegations": [
                {
                    "id": "auditman-0a1b2c3d4e5f67890",
                    "assessmentName": "prod-assessment-01",
                    "assessmentId": "auditman-0a1b2c3d4e5f67890",
                    "status": "ACTIVE",
                    "roleArn": "arn:aws:auditmanager:us-east-1:123456789012:assessment/prod-assessment-01",
                    "roleType": "ASSESSMENT",
                    "creationTime": "prod-assessment-01",
                    "lastUpdated": "prod-assessment-01",
                    "controlSetId": "auditman-0a1b2c3d4e5f67890",
                    "comment": "prod-assessment-01",
                    "createdBy": "prod-assessment-01"
                }
            ],
            "creationTime": 1704067200.0,
            "lastUpdated": 1704067200.0
        }
    ],
    "nextToken": ""
}
```

### 25. outposts list-outposts

- 응답시간: `531ms`
- exit_code: `0`
- route_source: `generic`
- 판단: 중간: schema 구조는 맞지만 값 의미는 검토 필요

```json
{
    "Outposts": [
        {
            "OutpostId": "outposts-0a1b2c3d4e5f67890",
            "OwnerId": "outposts-0a1b2c3d4e5f67890",
            "OutpostArn": "arn:aws:outposts:us-east-1:123456789012:outpost/prod-outpost-01",
            "SiteId": "outposts-0a1b2c3d4e5f67890",
            "Name": "prod-outpost-01",
            "Description": "Production outpost resource",
            "LifeCycleStatus": "ACTIVE",
            "AvailabilityZone": "prod-outpost-01",
            "AvailabilityZoneId": "outposts-0a1b2c3d4e5f67890",
            "Tags": {
                "Environment": "prod-outpost-01"
            },
            "SiteArn": "arn:aws:outposts:us-east-1:123456789012:outpost/prod-outpost-01",
            "SupportedHardwareType": "OUTPOST"
        }
    ]
}
```

### 26. appflow list-flows

- 응답시간: `546ms`
- exit_code: `0`
- route_source: `generic`
- 판단: 중간: schema 구조는 맞지만 값 의미는 검토 필요

```json
{
    "flows": [
        {
            "flowArn": "arn:aws:appflow:us-east-1:123456789012:flow/prod-flow-01",
            "description": "Production flow resource",
            "flowName": "prod-flow-01",
            "flowStatus": "Active",
            "sourceConnectorType": "Salesforce",
            "sourceConnectorLabel": "Salesforce",
            "destinationConnectorType": "S3",
            "destinationConnectorLabel": "S3",
            "triggerType": "Scheduled",
            "createdAt": 1704067200.0,
            "lastUpdatedAt": 1704067200.0,
            "createdBy": "arn:aws:iam::123456789012:user/data-ops",
            "lastUpdatedBy": "arn:aws:iam::123456789012:user/data-ops",
            "tags": {
                "Environment": "prod-flow-01"
            },
            "lastRunExecutionDetails": {
                "mostRecentExecutionMessage": "Execution completed successfully",
                "mostRecentExecutionTime": 1704067200.0,
                "mostRecentExecutionStatus": "Successful"
            }
        }
    ],
    "nextToken": ""
}
```

### 27. healthomics list-runs

- 응답시간: `447ms`
- exit_code: `2`
- route_source: `-`
- 판단: 실패/보강 필요
- 특이사항: 서버 요청 전 AWS CLI 로컬 단계에서 실패. 현재 설치된 AWS CLI에는 `healthomics` command가 없고, 관련 서비스명은 `omics`로 노출됨.

```text
usage: 
Note: AWS CLI version 2, the latest major version of the AWS CLI, is now stable and recommended for general use. For more information, see the AWS CLI version 2 installation instructions at: https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html

usage: aws [options] <command> <subcommand> [<subcommand> ...] [parameters]
To see help text, you can run:

  aws help
  aws <command> help
  aws <command> <subcommand> help
aws: error: argument command: Invalid choice, valid choices are:

accessanalyzer                           | account                                 
acm                                      | acm-pca                                 
aiops                                    | amp                                     
amplify                                  | amplifybackend                          
amplifyuibuilder                         | apigateway                              
apigatewaymanagementapi                  | apigatewayv2                            
appconfig                                | appconfigdata                           
appfabric                                | appflow                                 
appintegrations                          | application-autoscaling                 
application-insights                     | application-signals                     
applicationcostprofiler                  | appmesh                                 
apprunner                                | appstream                               
appsync                                  | arc-region-switch                       
arc-zonal-shift                          | artifact                                
athena                                   | auditmanager                            
autoscaling                              | autoscaling-plans                       
b2bi                                     | backup                                  
backup-gateway                           | backupsearch                            
batch                                    | bcm-dashboards                          
bcm-data-exports                         | bcm-pricing-calculator                  
bcm-recommended-actions                  | bedrock                                 
bedrock-agent                            | bedrock-agent-runtime                   
bedrock-agentcore                        | bedrock-agentcore-control               
bedrock-data-automation                  | bedrock-data-automation-runtime         
bedrock-runtime                          | billing                                 
billingconductor                         | braket                                  
budgets                                  | ce                                      
chatbot                                  | chime                                   
chime-sdk-identity                       | chime-sdk-media-pipelines               
chime-sdk-meetings                       | chime-sdk-messaging                     
chime-sdk-voice                          | cleanrooms                              
cleanroomsml                             | cloud9                                  
cloudcontrol                             | clouddirectory                          
cloudformation                           | cloudfront                              
cloudfront-keyvaluestore                 | cloudhsm                                
cloudhsmv2                               | cloudsearch                             
cloudsearchdomain                        | cloudtrail                              
cloudtrail-data                          | cloudwatch                              
codeartifact                             | codebuild                               
codecatalyst                             | codecommit                              
codeconnections                          | codeguru-reviewer                       
codeguru-security                        | codeguruprofiler                        
codepipeline                             | codestar-connections                    
codestar-notifications                   | cognito-identity                        
cognito-idp                              | cognito-sync                            
comprehend                               | comprehendmedical                       
compute-optimizer                        | compute-optimizer-automation            
connect                                  | connect-contact-lens                    
connectcampaigns                         | connectcampaignsv2                      
connectcases                             | connecthealth                           
connectparticipant                       | controlcatalog                          
controltower                             | cost-optimization-hub                   
cur                                      | customer-profiles                       
databrew                                
... [truncated: full raw output is in /tmp/dowon_40cmd_eval_20260517_194328/outputs/27.out]
```

### 28. mgn describe-source-servers

- 응답시간: `594ms`
- exit_code: `255`
- route_source: `generic`
- 판단: 실패/보강 필요
- 특이사항: turn_agent generic 경로까지 갔지만 응답 shape가 AWS CLI 역직렬화 기대와 맞지 않아 클라이언트 에러 발생. mgn 전용 template 또는 generic renderer 보강 필요.

```text
'str' object has no attribute 'get'
```

### 29. codeguru-reviewer list-repository-associations

- 응답시간: `588ms`
- exit_code: `0`
- route_source: `generic`
- 판단: 중간: schema 구조는 맞지만 값 의미는 검토 필요

```json
{
    "RepositoryAssociationSummaries": [
        {
            "AssociationArn": "arn:aws:codeguru-reviewer:us-east-1:123456789012:repository-association/prod-repository-association-01",
            "ConnectionArn": "arn:aws:codeguru-reviewer:us-east-1:123456789012:repository-association/prod-repository-association-01",
            "LastUpdatedTimeStamp": 1704067200.0,
            "AssociationId": "codeguru-0a1b2c3d4e5f67890",
            "Name": "prod-repository-association-01",
            "Owner": "prod-repository-association-01",
            "ProviderType": "REPOSITORY-ASSOCIATION",
            "State": "prod-repository-association-01"
        }
    ]
}
```

### 30. backup-gateway list-gateways

- 응답시간: `599ms`
- exit_code: `0`
- route_source: `generic`
- 판단: 중간: schema 구조는 맞지만 값 의미는 검토 필요

```json
{
    "Gateways": [
        {
            "GatewayArn": "arn:aws:backup-gateway:us-east-1:123456789012:gateway/prod-gateway-01",
            "GatewayDisplayName": "prod-backup-gateway-01",
            "GatewayType": "BACKUP_VM",
            "HypervisorId": "backupga-0a1b2c3d4e5f67890",
            "LastSeenTime": 1704067200.0
        }
    ]
}
```

### 31. ssm describe-instance-information

- 응답시간: `611ms`
- exit_code: `0`
- route_source: `state`
- 판단: 좋음: fake state 기반, 세션 일관성 우수

```json
{
    "InstanceInformationList": [
        {
            "InstanceId": "i-0abc1234def567890",
            "PingStatus": "Online",
            "LastPingDateTime": 1709251200,
            "AgentVersion": "3.2.2303.0",
            "IsLatestVersion": true,
            "PlatformType": "Linux",
            "PlatformName": "Amazon Linux",
            "PlatformVersion": "2023",
            "ResourceType": "EC2Instance",
            "IPAddress": "10.0.12.45",
            "ComputerName": "prod-bastion-01"
        }
    ]
}
```

### 32. ecr batch-check-layer-availability

- 응답시간: `550ms`
- exit_code: `0`
- route_source: `template`
- 판단: 좋음: 명시 template, 요청값 반영 가능

```json
{
    "layers": [
        {
            "layerDigest": "sha256:abc",
            "layerAvailability": "AVAILABLE",
            "layerSize": 7340032,
            "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip"
        }
    ],
    "failures": []
}
```

### 33. ecr get-download-url-for-layer

- 응답시간: `581ms`
- exit_code: `0`
- route_source: `template`
- 판단: 좋음: 명시 template, 요청값 반영 가능

```json
{
    "downloadUrl": "https://prod-ecr-layers.s3.us-east-1.amazonaws.com/demo/sha256-abc.tar.gz?X-Amz-Expires=900",
    "layerDigest": "sha256:abc"
}
```

### 34. ecr initiate-layer-upload

- 응답시간: `542ms`
- exit_code: `0`
- route_source: `template`
- 판단: 좋음: 명시 template, 요청값 반영 가능

```json
{
    "uploadId": "upload-000000000000demo",
    "partSize": 10485760
}
```

### 35. ecr complete-layer-upload

- 응답시간: `542ms`
- exit_code: `0`
- route_source: `template`
- 판단: 좋음: 명시 template, 요청값 반영 가능

```json
{
    "registryId": "123456789012",
    "repositoryName": "demo",
    "uploadId": "test",
    "layerDigest": "sha256:abc"
}
```

### 36. iam get-context-keys-for-principal-policy

- 응답시간: `671ms`
- exit_code: `0`
- route_source: `template`
- 판단: 좋음: 명시 template, 요청값 반영 가능

```json
{
    "ContextKeyNames": [
        "aws:PrincipalArn",
        "aws:username",
        "aws:CurrentTime",
        "aws:SourceIp"
    ]
}
```

### 37. iam list-service-specific-credentials

- 응답시간: `567ms`
- exit_code: `0`
- route_source: `template`
- 판단: 좋음: 명시 template, 요청값 반영 가능

```json
{
    "ServiceSpecificCredentials": [
        {
            "UserName": "victim-admin",
            "Status": "Active",
            "ServiceUserName": "victim-admin@example.com",
            "CreateDate": "2024-02-20T04:12:00Z",
            "ServiceSpecificCredentialId": "ACCAEXAMPLESERVICE01",
            "ServiceName": "codecommit.amazonaws.com"
        }
    ]
}
```

### 38. iam generate-service-last-accessed-details

- 응답시간: `521ms`
- exit_code: `0`
- route_source: `template`
- 판단: 좋음: 명시 template, 요청값 반영 가능

```json
{
    "JobId": "job-2uservictimadmin"
}
```

### 39. secretsmanager validate-resource-policy

- 응답시간: `588ms`
- exit_code: `0`
- route_source: `template`
- 판단: 좋음: 명시 template, 요청값 반영 가능

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

### 40. sts decode-authorization-message

- 응답시간: `510ms`
- exit_code: `0`
- route_source: `template`
- 판단: 좋음: 명시 template, 요청값 반영 가능

```json
{
    "DecodedMessage": "{\"allowed\":false,\"explicitDeny\":false,\"matchedStatements\":[],\"failures\":[],\"context\":{\"principal\":{\"id\":\"AIDAEXAMPLEAUDIT\",\"arn\":\"arn:aws:iam::123456789012:user/prod-audit\"},\"action\":\"iam:AttachUserPolicy\",\"resource\":\"arn:aws:iam::123456789012:user/prod-audit\",\"conditions\":{\"items\":[{\"key\":\"aws:PrincipalArn\",\"values\":[\"arn:aws:iam::123456789012:user/prod-audit\"]}]}}}"
}
```

## 5. 보완 우선순위

1. EC2 빈 응답 계열: `monitor-instances`, `unmonitor-instances`, `describe-reserved-instances`, `describe-reserved-instances-listings`, `purchase-reserved-instances-offering`, `describe-volume-status`, `create-spot-datafeed-subscription`, `describe-bundle-tasks`는 exit code는 성공이지만 응답 본문이 비어 있다. 허니팟 기만 품질 기준에서는 EC2 template 또는 EC2 XML generic renderer가 1순위 보강이다.
2. `mgn describe-source-servers`: generic 응답 shape가 AWS CLI parser와 맞지 않아 실패했다. 전용 template 추가가 필요하다.
3. `cloudformation describe-stack-resources`, `organizations list-roots`: native Moto 빈 상태/오류가 그대로 노출된다. 허니팟 기만 품질을 높이려면 weak native override 또는 template을 추가하는 것이 좋다.
4. `healthomics list-runs`: 현재 AWS CLI에서는 `healthomics` 서비스명이 유효하지 않았다. 테스트 명령어를 `omics list-runs`로 바꿔 재평가해야 한다.
5. `bedrock/resource-explorer/auditmanager/outposts` 등 generic 응답은 구조는 통과하지만 값 의미가 어색한 필드가 있다. 반복 사용되는 API부터 template 승격 후보로 기록하면 된다.
6. ECR 명령은 입력값이 그대로 반영되어 이전 generic보다 품질이 개선됐지만, `sha256:abc`처럼 실제 형식상 invalid한 digest도 성공 처리된다. 엄밀한 AWS 호환성을 원하면 validator에 SHA256 길이 검증을 추가해야 한다.
