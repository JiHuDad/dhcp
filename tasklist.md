
⸻

목표 한 줄 요약
	•	dhclient -6를 기반으로,
	•	Request에 VSO(옵션 17) 내부 서브옵션 71/72/73/74를 넣고,
	•	Reply의 서브옵션 77(PEM 2개, space 구분)을 파싱해 파일로 저장,
	•	모든 코드/경로/엔터프라이즈 번호는 설정 파일로 변경 가능.
	•	데모 우선: 로컬 테스트 하니스(가짜 DHCPv6 서버 스크립트)로 동작 확인까지 1주 내 완료.

⸻

기술 선택 (결정 고정)
	•	언어: C (dhclient 패치) + Python(테스트 하니스만)
	•	Crypto: OpenSSL(libcrypto)
	•	설정: TOML (가벼움 + 가독성)
	•	로그: 단순 텍스트 + 레벨(INFO/DEBUG/ERROR)
	•	배포: 단일 바이너리 + 샘플 systemd 유닛 (옵션)

⸻

저장소 구조(제안)

vendor-dhcp6/
├─ src/
│  ├─ dhcp6_vendor.c            # VSO 조립/파싱, Reply 77 처리
│  ├─ dhcp6_vendor.h
│  ├─ cfg.c / cfg.h             # TOML 파서(벤더 옵션/경로/엔터프라이즈 등)
│  ├─ crypto.c / crypto.h       # SHA256, RSA 서명, Base64
│  ├─ log.c / log.h
│  ├─ integrate_dhclient.c      # dhclient 훅 래퍼(송신/수신 인터셉트)
│  └─ util.c / util.h
├─ include/                     # (필요 시)
├─ third_party/
│  └─ toml                        # 임베디드 가능한 소형 TOML 파서(단일 C)
├─ tests/
│  ├─ unit/                     # 모듈 단위 테스트 (C)
│  ├─ it/                       # 통합(가짜 서버)
│  │  └─ fake_dhcp6_server.py   # Advertise/Reply 생성 (scapy 기반)
│  └─ vectors/                  # 정적 벡터(바이너리 덤프)
├─ conf/
│  ├─ vendor-dhcp6.toml         # 샘플 설정
│  └─ systemd.service.sample
├─ scripts/
│  ├─ gen_keypair.sh            # RSA 키/요청용 cert 준비
│  ├─ run_demo.sh               # 데모 시나리오 실행(클라/서버/패킷덤프)
│  └─ mkdirs.sh                 # 권한 포함 디렉터리 준비
├─ Makefile
└─ README.md


⸻

설정 파일 (샘플: conf/vendor-dhcp6.toml)

[dhcp6]
iface = "eth0"
duid_path = "/var/lib/vendor-dhcp6/duid"
timeout_seconds = 30

[vendor]
enterprise = 99999
sn_env = "SN_NUMBER"
code_sn = 71
code_sig = 72
code_cert_req = 73
code_sig_dup = 74
code_cert_reply = 77

[paths]
private_key = "/etc/vendor/keys/client.key"        # PEM (RSA-2048)
request_cert = "/etc/vendor/certs/request.pem"     # subopt 73에 그대로 탑재
reply_cert0 = "/var/lib/vendor-dhcp6/server0.pem"
reply_cert1 = "/var/lib/vendor-dhcp6/server1.pem"
reply_chain_bundle = "/var/lib/vendor-dhcp6/server_chain.pem"

[advertise_gate]
enabled = true
require_vendor = true
require_vendor_subopt = 90   # 예: Advertise에 벤더 서브옵션 90 존재해야 통과

[logging]
level = "info"
path  = "/var/log/vendor-dhcp6.log"
hex_dump = false


⸻

데이터 형식(고정)
	•	DHCPv6 Vendor-Specific Information (Option 17)
	•	enterprise-number (4B, BE)
	•	반복 서브옵션: code(2B,BE) | length(2B,BE) | value(NB)
	•	서브옵션
	•	71: SN_NUMBER 문자열(UTF-8, 선/후행 공백 trim, 중간 공백 보존)
	•	72: RSA(PKCS#1 v1.5, SHA256) 서명 바이트 Base64 문자열
	•	73: PEM 인증서 텍스트 원문(헤더/푸터 포함)
	•	74: 72와 동일(Base64 복제)
	•	77: Reply에서 수신. PEM1 + 0x20 + PEM2

⸻

핵심 흐름 (FSM Hook 설계)
	1.	Advertise 수신 시
	•	advertise_gate.enabled가 true면 Advertise에
	•	(a) VSO(enterprise==설정값) 존재?
	•	(b) 그 안에 require_vendor_subopt 존재?
	•	불충족 → Request 전송 중단(기본), 또는 설정으로 “VSO 없이 진행” 모드 지원(후순위)
	2.	Request 송신 직전
	•	VSO(enterprise=설정값) 구성
	•	71: getenv(sn_env)
	•	72: SHA256(SN) → RSA_sign → Base64
	•	73: request_cert 파일 전체 텍스트 로드
	•	74: 72 값 복제
	•	서브옵션 순서 고정: 71→72→73→74
	3.	Reply 수신 시
	•	VSO(enterprise=설정값)의 서브옵션 77 찾기
	•	공백(1회 이상)으로 두 PEM 문자열 분리
	•	각 PEM의 헤더/푸터 존재 검증
	•	reply_cert0, reply_cert1 저장(+ 번들 파일 선택 저장)
	•	권한: 파일 0640, 디렉터리 0750/0700 권장

⸻

상세 작업 분해 (주니어 할당 기준)

A. 공통 인프라

A1. 빌드 스캐폴드 (0.5d)
	•	Makefile: -lcrypto 링크, -Wall -Wextra -O2
	•	third_party/toml 단일C 파서 포함
	•	산출물: vendor-dhclient (dhclient에 벤더 로직을 링크하는 형태)

A2. TOML 설정 파서 (0.5d)
	•	cfg.{c,h}: 위 키 전부 파싱, 기본값 적용, 경로 존재/권한 체크
	•	유효성: enterprise ∈ [1..2^32-1], 코드들 ∈ [1..65535]

A3. 로깅 (0.5d)
	•	log_{info,debug,error}() + 파일/콘솔 동시 출력 옵션
	•	hex_dump 플래그 시 TLV 바이트 16진수 덤프

A4. 디렉터리 준비 스크립트 (0.5d)
	•	scripts/mkdirs.sh : /var/lib/vendor-dhcp6, /etc/vendor/{keys,certs} 생성 및 권한 설정

B. Crypto & Util

B1. Crypto 모듈 (1d)
	•	crypto_load_private_key(path, passphrase?)
	•	crypto_sha256(data,in_len, out32)
	•	crypto_rsa_sign_sha256(priv, data, sig_buf, &sig_len)
	•	base64_encode(in, in_len, out_str, out_cap)
	•	유닛 테스트: 고정 벡터로 서명 후 길이/복원 체크

B2. Util 모듈 (0.5d)
	•	read_file_all(path, &buf, &len)
	•	write_file(path, data, len, mode=0640)
	•	trim_spaces_inplace(char*) (선/후행만)

C. VSO 조립/파싱

C1. TLV 조립기 (0.5d)
	•	vso_append(buf, cap, code, value_ptr, value_len) → code(2) len(2) value
	•	실패 시 ENOSPC 리턴

C2. Request VSO 빌더 (0.5d)
	•	build_request_vso(cfg, out_buf, out_cap)
	•	71: SN env
	•	72: sign(Base64)
	•	73: cert 텍스트
	•	74: 72 복제
	•	VSO = enterprise(4B) + TLV들

C3. Advertise Gate 검사기 (0.5d)
	•	check_advertise_gate(cfg, adv_packet)
	•	VSO/서브옵션 존재 판단 (최초 1개만)

C4. Reply 77 파서 (0.5d)
	•	parse_reply_77_and_save(cfg, vso_payload)
	•	공백 분리 → PEM 두 개 검증 → 파일 저장(+bundle 옵션)

D. dhclient 통합(핵심)

주: 기존 dhclient 송수신 경로에 최소 침습 Hook 함수만 추가. 내부 심볼 이름에 의존적 구현을 피하기 위해, “송신 버퍼 최종 조립 직전”과 “수신 패킷 옵션 파싱 이후” 두 지점에 래퍼를 배치. 구체 진입지점은 소스 주석으로 명시.

D1. 송신 훅 (1d)
	•	Request 메시지 빌드 직전에 build_request_vso() 호출→ Option 17 블록 추가
	•	길이 갱신/정렬 보장
	•	디버그: VSO Hex dump

D2. 수신 훅 (1d)
	•	Reply 수신 후 옵션 파싱 단계에서 enterprise==설정값인 VSO 검색
	•	77 존재 시 parse_reply_77_and_save()
	•	결과/에러 로깅

D3. Advertise 훅 (0.5d)
	•	Solicit→Advertise 수신 시 check_advertise_gate()
	•	false면 이후 Request 중단(정책 로그 후 종료 코드 10)

E. 테스트 & 데모

E1. 유닛 테스트 (0.5d)
	•	crypto, vso, util 전용

E2. 가짜 DHCPv6 서버 (1d)
	•	tests/it/fake_dhcp6_server.py (scapy)
	•	Advertise 전송(필요시 VSO+subopt90 포함)
	•	Reply 전송(VSO+subopt77에 PEM1 + space + PEM2)
	•	포트/링크로컬/트랜잭션 ID 단순화(데모 목적)
	•	tests/vectors/에 샘플 PEM 2개 제공

E3. 데모 스크립트 (0.5d)
	•	scripts/run_demo.sh
	•	SN_NUMBER export
	•	RSA 키/요청용 cert 생성(scripts/gen_keypair.sh)
	•	가짜 서버 실행 → 클라이언트 실행 → 결과 파일 확인
	•	로그 tail & hexdump

E4. 수용 테스트(AC) 자동화 (0.5d)
	•	성공 조건:
	•	Request에 71/72/73/74 정확 포함(패킷 덤프 검사)
	•	72/74 동일(Base64 문자열 비교)
	•	Reply 수신 후 서버 cert 두 파일 생성(내용 길이/헤더 검증)

총합 예상 공수: 6.57.5일(1명 기준)
→ 2~3명 병렬 시 5영업일 내 충분.

⸻

함수 시그니처(가이드)

// cfg.h
typedef struct {
  struct {
    char *iface;
    char *duid_path;
    int   timeout_seconds;
  } dhcp6;

  struct {
    uint32_t enterprise;
    char *sn_env;
    uint16_t code_sn, code_sig, code_cert_req, code_sig_dup, code_cert_reply;
  } vendor;

  struct {
    char *private_key;
    char *request_cert;
    char *reply_cert0;
    char *reply_cert1;
    char *reply_chain_bundle; // optional
  } paths;

  struct {
    bool enabled;
    bool require_vendor;
    int  require_vendor_subopt; // -1 if disabled
  } advertise_gate;

  struct {
    char *path;
    char *level; // "info"|"debug"|"error"
    bool hex_dump;
  } logging;
} app_cfg_t;

int cfg_load(const char *path, app_cfg_t *out);
void cfg_free(app_cfg_t *cfg);

// crypto.h
typedef struct openssl_privkey privkey_t; // 내부 opaque
int crypto_load_private_key(const char *path, privkey_t **out);
int crypto_sha256(const uint8_t *in, size_t n, uint8_t out32[32]);
int crypto_rsa_sign_sha256(privkey_t *k, const uint8_t *in, size_t n,
                           uint8_t *sig, size_t *siglen);
char *base64_encode(const uint8_t *in, size_t n); // malloc 반환

// dhcp6_vendor.h
int build_request_vso(const app_cfg_t *cfg, uint8_t *out, size_t cap, size_t *used);
bool check_advertise_gate(const app_cfg_t *cfg, const uint8_t *pkt, size_t len);
int parse_reply_77_and_save(const app_cfg_t *cfg, const uint8_t *vso, size_t vso_len);


⸻

개발/실행 가이드 (요약)
	1.	키/요청용 cert 준비

./scripts/mkdirs.sh
./scripts/gen_keypair.sh  # /etc/vendor/keys/client.key, /etc/vendor/certs/request.pem
export SN_NUMBER=ABC123456

	2.	빌드/실행

make -j
sudo ./vendor-dhclient --config ./conf/vendor-dhcp6.toml --iface eth0

	3.	데모(가짜 서버)

./scripts/run_demo.sh
# 완료 후:
ls -l /var/lib/vendor-dhcp6/server0.pem /var/lib/vendor-dhcp6/server1.pem


⸻

로그 & 에러 정책
	•	성공 경로
	•	INFO 인터페이스/TxID/서버 링크로컬
	•	DEBUG Advertise 게이트 통과 여부
	•	INFO Request: VSO 추가 완료(코드:71,72,73,74)
	•	INFO Reply: subopt 77 저장 완료(경로 표시)
	•	대표 에러 코드
	•	2: 네트워크 타임아웃
	•	3: 설정/환경변수 없음(SN 미설정 등)
	•	4: 키 로드/서명 실패
	•	5: Reply 77 파싱/저장 실패
	•	10: Advertise 게이트 미충족으로 중단
	•	민감정보 마스킹
	•	SN 원문/서명 바이트/키 패스프레이즈는 로그에 출력 금지
	•	Base64는 앞 8자만 미리보기(나머지 ‘…’)

⸻

테스트 케이스 (필수)
	1.	정상 플로우
	•	Advertise에 require 조건 포함 → Request VSO(71/72/73/74) 송신 → Reply 77 수신 → 파일 2개 저장 OK
	2.	SN 미설정
	•	SN_NUMBER 없음 → 71/72/74 생성 실패 → 종료 코드 3
	3.	키 불일치/서명 실패
	•	잘못된 키 → 72/74 생성 실패 → 종료 코드 4
	4.	77 이상/이하 개수
	•	PEM 하나만 / 세 개 이상 / 구분자 불량 → 5로 실패, 저장 안 함
	5.	서브옵션 코드 변경
	•	TOML로 코드값 바꾸고 동일 시나리오 재통과
	6.	광역 방어
	•	광고(Advertise) 게이트 off/on 모드 별 동작 확인

⸻

역할/일정 배분(5영업일)
	•	D1 (월)
	•	Dev1: A1/A2/A3 (빌드/설정/로그)
	•	Dev2: B1 (Crypto), B2(Util)
	•	D2 (화)
	•	Dev1: C1/C2 (VSO 조립/Request 빌더)
	•	Dev2: C3(Advertise Gate), 유닛테스트
	•	D3 (수)
	•	Dev1: D1(송신 훅)
	•	Dev2: D2(수신 훅) + D3(Advertise 훅)
	•	D4 (목)
	•	Dev1: E2(가짜 서버) + E3(데모 스크립트)
	•	Dev2: E1/E4(유닛/수용 자동화) + 로그/권한 마무리
	•	D5 (금)
	•	합동: 종단 시연, README/운영 가이드 정리, 리팩토링/버그픽스

⸻

수용 기준(Acceptance Criteria)
	1.	Request 패킷에 Option17(enterprise=설정값) 존재, 내부에 71/72/73/74 정확히 포함(순서 71→72→73→74).
	2.	72와 74의 Base64 값 동일. 72/74 원본은 SN_NUMBER에 대한 RSA-SHA256 서명임(검증 스크립트로 확인).
	3.	Reply 수신 후 subopt 77에서 PEM 2개를 분리하여 설정 경로에 저장(파일 권한/내용 검증).
	4.	TOML에서 서브옵션 코드/경로/엔터프라이즈 번호 변경만으로 동작 수정 가능.
	5.	에러 상황별 종료 코드와 의미 있는 로그 남김.

⸻

리스크/우회안 (이미 반영)
	•	dhclient 내부 진입 지점 명칭 차이: “최종 조립 직전/파싱 직후”에 래퍼 Hook를 두고, 내부 심볼 의존 최소화(코멘트로 패치 위치 명시).
	•	실망스러운 네트워크 환경(라보 장비 없음): 가짜 서버로 최초 결과 확보(패킷 레벨).
	•	서명/인증서 에지 케이스: 최소 파싱 검증만 수행, 체인 검증은 비범위.

⸻

