# DHCPv6 Vendor-Specific Options Integration Design

## 개요

현재 `vendor-dhcp6/` 디렉토리에 독립적으로 구현된 DHCPv6 vendor-specific options (VSO) 기능을 기존 ISC DHCP 코드베이스에 통합하기 위한 설계 문서입니다.

## 현재 상황 분석

### vendor-dhcp6/ 구현 분석

#### 핵심 기능
- **DHCPv6 VSO (Option 17) 처리**: Enterprise Number + Sub-options 구조
- **암호화 기능**: RSA-2048/SHA-256 서명, Base64 인코딩, PEM 인증서 처리
- **설정 관리**: TOML 기반 설정 시스템
- **로깅 시스템**: 레벨별 로깅, HEX 덤프, 민감정보 마스킹
- **클라이언트 구현**: Solicit → Advertise → Request → Reply 시퀀스

#### 주요 컴포넌트
```
vendor-dhcp6/
├── src/
│   ├── dhcp6_vendor.c    # VSO TLV 처리, 인증서 파싱
│   ├── crypto.c          # OpenSSL 래퍼, RSA 서명
│   ├── cfg.c             # TOML 설정 파서
│   ├── log.c             # 로깅 시스템
│   ├── util.c            # 유틸리티 함수
│   └── main.c            # DHCPv6 소켓 통신
├── include/              # 헤더 파일들
└── tests/               # 단위/통합 테스트
```

### 기존 ISC DHCP 구조 분석

#### DHCPv6 관련 파일들
- **server/dhcpv6.c**: DHCPv6 서버 메인 로직
- **includes/dhcp6.h**: DHCPv6 프로토콜 정의 (D6O_VENDOR_OPTS = 17)
- **common/options.c**: 옵션 처리 프레임워크
- **common/tables.c**: 옵션 테이블 정의

#### 기존 Vendor Options 지원
- **D6O_VENDOR_CLASS (16)**: Vendor Class Identifier
- **D6O_VENDOR_OPTS (17)**: Vendor-Specific Information Options
- **vendor-option-space**: 설정을 통한 vendor option space 정의
- **Enterprise Number 기반 옵션 캡슐화**

## 통합 아키텍처 설계

### 1. 통합 전략

#### A. 서버 사이드 통합 (우선순위: 높음)
기존 ISC DHCP 서버에 vendor-specific options 처리 기능을 통합

#### B. 클라이언트 사이드 통합 (우선순위: 중간)
기존 ISC DHCP 클라이언트에 VSO 처리 기능을 추가

#### C. 공통 라이브러리 통합 (우선순위: 높음)
vendor-dhcp6의 핵심 기능을 common/ 라이브러리로 이식

### 2. 파일 구조 설계

```
dhcp/
├── common/
│   ├── vendor_options.c      # NEW: VSO 처리 공통 함수
│   ├── crypto_utils.c        # NEW: 암호화 유틸리티
│   └── config_parser.c       # NEW: 확장된 설정 파서
├── includes/
│   ├── vendor_options.h      # NEW: VSO 처리 헤더
│   ├── crypto_utils.h        # NEW: 암호화 헤더
│   └── dhcp6.h              # MODIFIED: VSO 상수 추가
├── server/
│   ├── dhcpv6.c             # MODIFIED: VSO 처리 통합
│   ├── vendor_handler.c     # NEW: Vendor 옵션 핸들러
│   └── dhcpd.conf.5         # MODIFIED: 새 설정 옵션 문서화
├── client/
│   ├── dhc6.c               # MODIFIED: VSO 클라이언트 지원
│   └── vendor_client.c      # NEW: Vendor 클라이언트 로직
└── tests/
    └── vendor_options_test.c # NEW: VSO 테스트 케이스
```

### 3. 핵심 컴포넌트 설계

#### 3.1 공통 VSO 처리 라이브러리 (common/vendor_options.c)

```c
// VSO 구조체 정의
struct vendor_option {
    u_int32_t enterprise_num;
    u_int16_t sub_option_code;
    u_int16_t sub_option_len;
    unsigned char *data;
};

// 핵심 함수들
int parse_vendor_option(struct data_string *vso_data,
                       struct vendor_option **options,
                       int *option_count);

int build_vendor_option(u_int32_t enterprise_num,
                       struct vendor_option *sub_options,
                       int sub_option_count,
                       struct data_string *result);

int validate_vendor_signature(struct vendor_option *option,
                             const char *public_key_path);

int create_vendor_signature(const char *data,
                           const char *private_key_path,
                           struct data_string *signature);
```

#### 3.2 암호화 유틸리티 (common/crypto_utils.c)

```c
// RSA 서명/검증
int rsa_sign_data(const unsigned char *data, size_t data_len,
                 const char *private_key_path,
                 unsigned char **signature, size_t *sig_len);

int rsa_verify_signature(const unsigned char *data, size_t data_len,
                        const unsigned char *signature, size_t sig_len,
                        const char *public_key_path);

// Base64 인코딩/디코딩
char *base64_encode(const unsigned char *data, size_t len);
int base64_decode(const char *encoded, unsigned char **decoded, size_t *len);

// PEM 인증서 처리
int load_pem_certificate(const char *path, struct data_string *cert);
int save_pem_certificate(const char *path, const struct data_string *cert);
int validate_pem_format(const struct data_string *cert);
```

#### 3.3 서버 사이드 VSO 핸들러 (server/vendor_handler.c)

```c
// Vendor 옵션 처리 설정
struct vendor_config {
    u_int32_t enterprise_num;
    char *private_key_path;
    char *certificate_path;
    int enabled_sub_options[16];  // 지원하는 서브옵션 코드들
    int require_signature;
    int auto_respond;
};

// 핵심 핸들러 함수들
int handle_vendor_request(struct packet *packet,
                         struct vendor_config *config,
                         struct option_state *options);

int process_vendor_sub_options(struct vendor_option *options,
                              int option_count,
                              struct vendor_config *config,
                              struct data_string *response);

int generate_vendor_response(struct vendor_config *config,
                            const struct data_string *request_data,
                            struct data_string *response);
```

### 4. 설정 시스템 통합

#### 4.1 dhcpd.conf 확장

```apache
# 기존 vendor-option-space 확장
vendor-option-space "enterprise-12345";

# 새로운 vendor-specific 설정 블록
vendor-config enterprise-12345 {
    # 기본 설정
    enabled true;
    auto-respond true;
    
    # 암호화 설정
    private-key "/etc/dhcp/vendor/private.key";
    certificate-chain "/etc/dhcp/vendor/cert_chain.pem";
    require-signature true;
    
    # 서브옵션 설정
    sub-option 71 {
        type "serial-number";
        source "client-request";
        validate true;
    }
    
    sub-option 72 {
        type "signature";
        algorithm "rsa-sha256";
        required true;
    }
    
    sub-option 73 {
        type "certificate";
        source "client-request";
        save-path "/var/lib/dhcp/client-certs/";
    }
    
    sub-option 77 {
        type "certificate-chain";
        source "server-response";
        certificate-chain "/etc/dhcp/vendor/response_chain.pem";
    }
}

# 호스트별 vendor 설정
host vendor-client-001 {
    hardware ethernet 00:11:22:33:44:55;
    vendor-config enterprise-12345;
    vendor-serial-number "ABC123456789";
}
```

#### 4.2 dhclient.conf 확장

```apache
# 클라이언트 vendor 설정
vendor-config enterprise-12345 {
    enabled true;
    
    # 클라이언트 인증 정보
    serial-number-env "SN_NUMBER";
    private-key "/etc/dhcp/client.key";
    request-certificate "/etc/dhcp/client_request.pem";
    
    # 응답 처리
    save-certificates "/var/lib/dhcp/server-certs/";
    verify-signature true;
    
    # 요청할 서브옵션들
    request-sub-options 71, 72, 73, 74;
    expect-sub-options 77;
}
```

### 5. 데이터 플로우 다이어그램

#### 5.1 서버 사이드 처리 플로우

```
[DHCPv6 Request] 
      ↓
[option parsing: dhcpv6.c]
      ↓
[VSO option detected (D6O_VENDOR_OPTS)]
      ↓
[vendor_handler.c: handle_vendor_request()]
      ↓
[vendor_options.c: parse_vendor_option()]
      ↓ 
[서브옵션별 처리]
      ├─ Sub-opt 71: Serial Number 검증
      ├─ Sub-opt 72: RSA 서명 검증 (crypto_utils.c)
      ├─ Sub-opt 73: 클라이언트 인증서 저장
      └─ Sub-opt 74: 중복 서명 검증
      ↓
[응답 생성: generate_vendor_response()]
      ├─ Sub-opt 77: 서버 인증서 체인 포함
      └─ Enterprise Number + 서브옵션들 캡슐화
      ↓
[vendor_options.c: build_vendor_option()]
      ↓
[DHCPv6 Reply with VSO]
```

#### 5.2 클라이언트 사이드 처리 플로우

```
[환경변수: SN_NUMBER]
      ↓
[DHCPv6 Solicit 전송]
      ↓
[Advertise 수신 및 Gate 검사]
      ↓
[Request 생성]
      ├─ VSO with Enterprise Number
      ├─ Sub-opt 71: SN_NUMBER
      ├─ Sub-opt 72: RSA 서명 (crypto_utils.c)
      ├─ Sub-opt 73: 요청 인증서
      └─ Sub-opt 74: 중복 서명
      ↓
[Request 전송]
      ↓
[Reply 수신]
      ↓
[VSO 파싱: parse_vendor_option()]
      ↓
[Sub-opt 77: 서버 인증서 체인 추출]
      ↓
[인증서 검증 및 저장]
```

### 6. 통합 단계별 계획

#### Phase 1: 공통 라이브러리 통합 (4주)

1. **Week 1-2**: 핵심 라이브러리 이식
   - `vendor-dhcp6/src/dhcp6_vendor.c` → `common/vendor_options.c`
   - `vendor-dhcp6/src/crypto.c` → `common/crypto_utils.c`
   - 헤더 파일들을 `includes/`로 이동

2. **Week 3-4**: 빌드 시스템 통합
   - `Makefile.am` 수정하여 새 파일들 포함
   - OpenSSL 의존성 설정
   - 단위 테스트 추가

#### Phase 2: 서버 사이드 통합 (6주)

1. **Week 1-2**: VSO 처리 로직 통합
   - `server/dhcpv6.c`에 VSO 감지 및 핸들링 추가
   - `server/vendor_handler.c` 구현

2. **Week 3-4**: 설정 시스템 확장
   - `dhcpd.conf` 파서에 vendor-config 블록 추가
   - 설정 검증 로직 구현

3. **Week 5-6**: 테스트 및 디버깅
   - 통합 테스트 케이스 작성
   - 기존 기능 regression 테스트

#### Phase 3: 클라이언트 사이드 통합 (4주)

1. **Week 1-2**: 클라이언트 로직 통합
   - `client/dhc6.c`에 VSO 처리 추가
   - `client/vendor_client.c` 구현

2. **Week 3-4**: 설정 및 테스트
   - `dhclient.conf` 확장
   - End-to-end 테스트

#### Phase 4: 문서화 및 최적화 (2주)

1. **Week 1**: 문서화
   - `dhcpd.conf.5`, `dhclient.conf.5` 매뉴얼 업데이트
   - 설정 예제 작성
   - 개발자 가이드 작성

2. **Week 2**: 성능 최적화 및 보안 검토
   - 메모리 누수 검사
   - 보안 취약점 점검
   - 성능 프로파일링

### 7. 호환성 고려사항

#### 7.1 기존 기능과의 호환성
- 기존 `vendor-option-space` 설정 유지
- 기존 DHCPv6 옵션 처리 로직 보존
- 새 기능은 명시적 활성화 시에만 동작

#### 7.2 버전 호환성
- ISC DHCP 4.4.x 브랜치와 호환
- 새 설정 옵션은 향후 버전에서만 사용 가능
- Legacy 설정 지원 유지

### 8. 보안 고려사항

#### 8.1 암호화 키 관리
- 프라이빗 키 파일 권한 검증 (0600)
- 키 로딩 시 메모리 보호
- 서명 생성 후 메모리 클리어

#### 8.2 입력 검증
- VSO 데이터 길이 검증
- PEM 인증서 형식 검증
- Base64 디코딩 시 버퍼 오버플로우 방지

#### 8.3 로깅 보안
- 민감정보 마스킹 (시리얼 번호, 서명)
- 로그 파일 권한 설정
- 디버그 모드에서의 추가 정보 출력

### 9. 테스트 전략

#### 9.1 단위 테스트
- VSO 파싱/생성 함수 테스트
- 암호화 함수 테스트
- 설정 파서 테스트

#### 9.2 통합 테스트
- 서버-클라이언트 간 VSO 교환 테스트
- 다양한 Enterprise Number 처리 테스트
- 오류 시나리오 테스트 (잘못된 서명, 인증서 등)

#### 9.3 성능 테스트
- 대량 클라이언트 동시 처리 테스트
- 메모리 사용량 측정
- CPU 사용률 분석

### 10. 마이그레이션 가이드

#### 10.1 기존 vendor-dhcp6 사용자
1. 설정 파일 변환 도구 제공
2. TOML → dhcpd.conf 변환 스크립트
3. 단계별 마이그레이션 가이드

#### 10.2 기존 ISC DHCP 사용자
1. 새 vendor-config 옵션 설명
2. 기존 설정과의 차이점 문서화
3. 점진적 도입 방안 제시

## 결론

이 설계안은 vendor-dhcp6의 기능을 ISC DHCP 메인 코드베이스에 안전하고 효율적으로 통합하는 방법을 제시합니다. 단계별 접근을 통해 기존 시스템의 안정성을 유지하면서도 새로운 vendor-specific options 기능을 완전히 통합할 수 있습니다.

핵심 목표:
- **기존 호환성 유지**: 현재 ISC DHCP 사용자에게 영향 없음
- **모듈화된 설계**: 새 기능을 독립적으로 활성화/비활성화 가능
- **확장 가능성**: 향후 다른 Enterprise Number 지원 용이
- **보안 강화**: 암호화 및 인증 기능 내장
- **운영 편의성**: 통합된 설정 시스템 및 로깅