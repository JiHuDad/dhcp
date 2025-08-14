
⸻

PRD: DHCPv6 클라이언트 — 벤더 전용 옵션 처리(ISC DHCP 기반)

0) 목적
	•	DHCP 서버의 Advertise/Reply에 따라 동작하는 전용 DHCPv6 클라이언트를 구현한다.
	•	Advertise가 특정 조건(특정 옵션 존재)을 만족한다고 가정하고, Request에 VSO(Option 17) 안에 서브옵션 71/72/73/74를 포함해 서버로 송신한다.
	•	Reply에서 서브옵션 77(인증서 체인 2개, PEM 형식, space로 구분)을 파싱하여 지정 경로에 저장한다.
	•	서브옵션 번호·엔터프라이즈 번호·값 생성 로직·파일 경로는 설정으로 변경 가능해야 한다.

주: “옵션 71/72/73/74/77”은 DHCPv6 최상위 코드가 아니라 VSO(Option 17) 내부의 벤더-서브옵션 코드로 정의/사용.

⸻

1) 범위(Scope)
	•	플랫폼: Linux (glibc, systemd 유무 무관), x86_64/ARM64
	•	권한: root 권장(UDP/546 바인드 및 네트워크 인터페이스 제어)
	•	네트워크: 단일 인터페이스(다중 인터페이스는 후순위)
	•	동작 흐름:
	1.	Solicit → Advertise 수신
	2.	Advertise 내 특정 옵션 존재를 확인(구체 조건은 설정화)
	3.	조건 충족 시 Request 전송(VSO 내 71/72/73/74 포함)
	4.	Reply 수신 → VSO 내 77 파싱 → 인증서 2개 저장
	•	클라이언트의 DUID/IAID 관리(파일 저장 포함)는 최소한으로 구현(기본 DUID-LLT 또는 DUID-LL)

비범위(Out of Scope)
	•	Prefix delegation(IA_PD), Rapid Commit, 재갱신(Renew/Relbind) 등 장기 임대 수명주기 최적화
	•	SLAAC 연계, 라우터 광고 처리
	•	고급 보안(예: DHCPv6 인증 옵션) 및 서버 인증 검증(선택적 부가 기능으로만 언급)
	•	복수 서버 후보 중 점수화 선택(최소 구현은 가장 먼저 조건을 만족한 Advertise 채택)

⸻

2) 용어/기본
	•	VSO(Option 17) = Vendor-specific Information. 구조:
	•	enterprise-number(4바이트, IANA에 등록된 Enterprise ID)
	•	Vendor sub-options: 반복되는 TLV(서브옵션코드(2B), 길이(2B), 값(NB))
	•	본 PRD에서 말하는 옵션 71/72/73/74/77은 위 서브옵션코드.

⸻

3) 기능 요구사항(Functional Requirements)

3.1 Advertise 처리
	•	클라이언트는 Solicit을 보내고 Advertise를 수신한다.
	•	존재 조건 검사(configurable):
	•	예시 A: Advertise 내 특정 최상위 옵션 코드의 존재 유무
	•	예시 B: Advertise 내 **VSO(Option 17)**에 지정 enterprise-number가 있고, 그 안에 지정 서브옵션 코드가 존재
	•	예시 C: 위 A/B를 조합한 표현식(AND/OR)까지 지원(초기 버전은 단일 조건 또는 단순 AND 지원)
	•	본 과제는 “존재한다” 가정으로 구현하되, 설정으로 껐다 켤 수 있는 조건 검사를 둔다.
	•	조건이 false일 때의 동작(후속 확장용):
	•	기본값: Request 송신을 중단하고 종료(또는 VSO 없이 Request 진행) — 설정으로 선택 가능.

3.2 Request 생성(핵심)
	•	Request 메시지에 VSO(Option 17) 포함:
	•	enterprise-number: 설정값(필수)
	•	서브옵션 71: 환경변수 SN_NUMBER 값 문자열(UTF-8)
	•	서브옵션 72: SN_NUMBER에 대해 SHA-256 해시 후, 지정 프라이빗 키로 서명한 바이트를 Base64 인코딩한 문자열
	•	기본 키 유형: RSA-2048, PKCS#1 v1.5 (설정으로 ECDSA/Ed25519는 후순위)
	•	해시: SHA-256 고정
	•	입력: 환경변수 SN_NUMBER의 바이트(개행 제거/트림 규칙 명시)
	•	서브옵션 73: 지정 경로의 PEM 인증서(단일개) 텍스트 원문(“—–BEGIN CERTIFICATE—– … —–END CERTIFICATE—–” 포함)
	•	서브옵션 74: 72와 동일 값 (Base64 문자열 복제)
	•	서브옵션 코드 번호(71/72/73/74)는 설정으로 변경 가능.
	•	VSO 내부 서브옵션 순서는 설정으로 고정하거나(71→72→73→74) 임의 순서 허용(기본: 고정 순서).

3.3 Reply 처리(핵심)
	•	Reply 내 **VSO(Option 17)**에서 서브옵션 77을 찾는다(서브옵션 번호/enterprise-number 모두 설정 기반).
	•	77의 값은 PEM 인증서 2개를 space로 구분한 문자열:
	•	예: -----BEGIN CERTIFICATE-----...-----END CERTIFICATE----- -----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----
	•	파싱 규칙:
	•	단일 space(0x20) 기준 최초 1회 분할(혹은 공백 시퀀스 1회 분할) — 설정으로 구분자 패턴 변경 가능(기본: 하나 이상의 공백을 단일 분리자로 간주)
	•	각 토막이 PEM 헤더/푸터를 모두 포함하는지 검증
	•	저장:
	•	cert_chain_0_path, cert_chain_1_path (설정값) 각각에 저장(파일 모드는 0640; 상위 디렉터리 권한/소유자 점검)
	•	추가 옵션: 단일 체인 파일로 결합 저장할 경로(cert_chain_bundle_path)도 지원(선택)
	•	유효성(선택): openssl로 기본 파싱 검증만 수행(만료·체인검증은 비범위)

3.4 설정 변경 가능 항목
	•	enterprise-number (uint32)
	•	서브옵션 코드: sn_number_code(기본 71), sn_sig_code(72), cert_req_code(73), sn_sig_dup_code(74), cert_reply_code(77)
	•	Advertise 존재 조건식(간단한 JSON/INI 키로 AND 묶음)
	•	SN_NUMBER 환경변수명(기본 SN_NUMBER)
	•	프라이빗 키 경로/형식(PEM), 키 유형(RSA 기본), 패스프레이즈 처리(환경변수/파일 참조)
	•	73에 사용할 요청용 인증서 경로
	•	77 저장 경로(개별/번들), 구분자 패턴
	•	네트워크 인터페이스명, 바인드 동작, 타임아웃/재전송 파라미터
	•	로깅 레벨/경로/형식(JSON 로그 옵션 등)

⸻

4) 비기능 요구사항(Non-Functional)

4.1 성능/신뢰성
	•	단일 인터페이스 기준, 단일 트랜잭션 왕복 시간은 네트워크 의존(수 초 내 완료).
	•	재전송/타임아웃 기본값: RFC 8415의 IRT/MRT/MRC 참고(최소 구현은 고정값 예: IRT=1s, MRT=120s, MRC=10)

4.2 보안
	•	프라이빗 키/인증서 파일 권한 검증(0600/0640)
	•	Base64 서명 생성 시 메모리 클리어(가능한 범위)
	•	로그에 민감정보 마스킹(서명 바이트, 키 경로 패스프레이즈 등)

4.3 운영
	•	단일 바이너리로 배포.
	•	systemd 서비스 유닛 샘플 제공.
	•	종료 코드 표준화(성공 0, 네트워크 타임아웃 2, 파일오류 3, 크립토오류 4 등)

⸻

5) 아키텍처 & 구현 개요

5.1 기반 선택
	•	**ISC DHCP 오픈 소스(dhclient)**를 포크하여 DHCPv6 경로에 VSO 생성/파싱 로직을 삽입하는 방안 권장.
	•	장점: 검증된 DHCPv6 상태 머신/타임아웃/패킷 인코딩·디코딩 재사용
	•	구현 포인트:
	•	Request 작성 시점에 VSO(Option 17) 주입
	•	Reply 파싱 경로에 VSO(Option 17) + 서브옵션 77 처리 분기 추가
	•	설정 파서(기존 dhclient.conf 확장 or 별도 TOML/INI) — 별도 설정파일 추천(독립적인 데모 도구로 운용하기 쉬움)
	•	대안(후순위): scapy/raw-socket으로 미니 DHCPv6 클라이언트 자작(개발 속도↑, 유지보수/안정성↓)

5.2 주요 모듈
	•	cfg: 설정 파서(INI/TOML). 환경변수 override 지원.
	•	crypto: SHA-256, RSA/PKCS#1 v1.5 서명, Base64 (OpenSSL libcrypto 활용)
	•	vso: Vendor Option 17 인코딩/디코딩(TLV)
	•	core: DHCPv6 FSM 훅(Advertise 검사, Request 주입, Reply 처리)
	•	io: 파일 입출력/권한/경로 보장
	•	log: 레벨 기반 로그 + HEX 덤프(디버그)
	•	cli: --iface, --config, --dry-run, --dump-packets 등

5.3 데이터 포맷
	•	서브옵션(TLV):
	•	code(2B, BE), len(2B, BE), value(NB)
	•	문자열 값은 그대로 바이트(UTF-8) 저장. Base64는 ASCII.
	•	VSO(Option 17):
	•	enterprise-number(4B, BE) + [subopt TLV]*

⸻

6) 구성(예시; TOML)

[dhcp6]
iface = "eth0"
duid_path = "/var/lib/vendor-dhcp6/duid"
timeout_seconds = 30

[vendor]
enterprise = 99999
sn_env = "SN_NUMBER"

# suboption codes (changeable)
code_sn = 71
code_sig = 72
code_cert_req = 73
code_sig_dup = 74
code_cert_reply = 77

[paths]
private_key = "/etc/vendor/keys/client.key"        # PEM (RSA-2048)
request_cert = "/etc/vendor/certs/request.pem"     # goes into subopt 73
reply_cert0 = "/var/lib/vendor-dhcp6/server0.pem"
reply_cert1 = "/var/lib/vendor-dhcp6/server1.pem"
reply_chain_bundle = "/var/lib/vendor-dhcp6/server_chain.pem"

[advertise_gate]
enabled = true
# Example: require presence of VSO with same enterprise and a suboption 90
require_vendor = true
require_vendor_subopt = 90

[logging]
level = "info"
path  = "/var/log/vendor-dhcp6.log"
hex_dump = false


⸻

7) 에러 처리 & 로깅
	•	에러 클래스: 설정오류, 환경변수 없음(SN_NUMBER 미설정), 키 로드 실패, 서명 실패, Advertise 미수신, Reply 미수신/파싱 실패, PEM 저장 실패
	•	로그 예:
	•	INFO: 인터페이스, 트랜잭션 ID, 수신 서버 DUID/링크로컬
	•	DEBUG: 수신 Advertise의 옵션 맵(요약), VSO 서브옵션 목록
	•	WARN: Advertise gate 미충족(정책상 중단/진행)
	•	ERROR: 77 파싱 실패(헤더/푸터 불일치, 분리 실패 등)

⸻

8) 보안/컴플라이언스 고려
	•	프라이빗 키는 0600, 디렉터리는 0700 권장. 루트 전용.
	•	로그에 SN_NUMBER 원문/서명 바이트 미출력(요약 hash만)
	•	설정파일 권한 0640 이하 권장
	•	(옵션) OpenSSL FIPS 모드 동작 호환성 점검

⸻

9) 테스트 전략

9.1 단위 테스트
	•	crypto: SN_NUMBER → SHA256 → RSA서명 → Base64 길이/복원 검증
	•	vso: TLV 인/디코드(경계값: 0바이트, 최대 길이)
	•	io: PEM 저장/권한/디렉터리 생성

9.2 통합 테스트
	•	가짜 DHCPv6 서버(Test harness)로 Advertise/Reply 시나리오 재현
	•	케이스:
	1.	Advertise gate 충족 → Request VSO 포함 전송 → Reply 77 수신 → 2개 파일 저장 OK
	2.	77 값이 PEM 1개만 포함 / 셋 이상 포함 / 구분자 불량 → 적절한 오류
	3.	SN_NUMBER 미설정 → 71/72/74 생성 실패 → 종료 코드/로그 확인
	4.	잘못된 키/패스프레이즈 → 서명 실패
	5.	설정된 서브옵션 코드 변경 시 반영 확인

9.3 수동 시연
	•	--dry-run: 패킷을 실제 전송하지 않고 Request 페이로드를 파일로 덤프(바이너리/HEX)
	•	--dump-packets: 송수신 DHCPv6 패킷 pcap 저장(디버깅용)

⸻

10) 수용 기준(Acceptance Criteria)
	1.	Advertise gate가 true일 경우, Request에 VSO(enterprise=설정값)가 들어가고 서브옵션 71/72/73/74가 정확히 포함된다.
	2.	72/74는 SN_NUMBER 기반 RSA-SHA256 서명(Base64) 이다(검증 스크립트로 원복 검증 가능).
	3.	Reply의 77에서 PEM 2개를 올바르게 분리·검증하고, 설정된 경로에 저장한다(권한·내용 확인).
	4.	모든 서브옵션 코드/경로/enterprise-number 변경이 설정만으로 가능하다.
	5.	오류 시 적절한 종료 코드와 로그가 남는다.

⸻

11) 오픈 이슈(결정 필요)
	•	Advertise gate의 “특정 옵션” 구체 정의(최상위 옵션? VSO 서브옵션? 코드 번호?)
	•	키 알고리즘 가변화(ECDSA/Ed25519 지원 일정)
	•	다중 인터페이스/IPv6 링크로컬 우선순위
	•	체인 저장 시 추가 검증(중간/루트 검증은 비범위지만 선택 기능으로 유용)

⸻

12) 개발 작업 분해(1주일 내 1차 버전 목표)

D0–D1
	•	저장소/빌드 스캐폴드(setup.sh, Makefile, CI 스켈레톤)
	•	설정 파서(TOML/INI) + 샘플 설정
	•	OpenSSL 연동(키 로드, SHA256, RSA sign, Base64)

D2
	•	VSO TLV 인코더/디코더 유닛 테스트
	•	Request 생성 루틴에 VSO 조립(71/72/73/74)

D3
	•	Advertise 파서 + 게이트 로직(최소 1개 조건)
	•	Reply 파서 + 77 추출/분리/PEM 저장

D4
	•	에러/로그/권한 점검
	•	dry-run/덤프 옵션

D5
	•	통합 테스트 하니스(모의 서버) 작성 + 주요 시나리오 자동화
	•	수용 기준 검토/수정

버퍼(D6–D7)
	•	리팩토링/성능·안정화/문서화(README, 설정 가이드, 운영 가이드)
	•	systemd 유닛 샘플/패키징 스크립트

⸻

13) 운영 가이드(요약)

실행 전
	•	/etc/vendor/keys/client.key(0600), /etc/vendor/certs/request.pem 준비
	•	SN_NUMBER 환경변수 설정(예: export SN_NUMBER=ABC123456)
	•	설정 파일 배치 /etc/vendor/dhcp6-vendor.conf

실행

sudo /usr/local/bin/dhcp6-vendor \
  --config /etc/vendor/dhcp6-vendor.conf \
  --iface eth0

확인
	•	로그: /var/log/vendor-dhcp6.log
	•	Reply 처리 후:
	•	/var/lib/vendor-dhcp6/server0.pem
	•	/var/lib/vendor-dhcp6/server1.pem
	•	(선택) /var/lib/vendor-dhcp6/server_chain.pem

⸻

14) 예외/엣지 케이스
	•	SN_NUMBER에 공백/개행 포함 → 트림 규칙: 선/후행 공백 제거, 중간 공백은 그대로 유지 (설정으로 변경 가능)
	•	77이 PEM 두 개가 아닌 경우:
	•	기본: 실패로 간주하고 저장하지 않음(종료 코드 5)
	•	설정으로 “첫 2개만 저장” 같은 관대 모드 추가 가능
	•	Advertise/Reply에 VSO가 복수 존재 시:
	•	동일 enterprise만 채택(최초 발견 1개)

⸻

15) 문서/산출물
	•	설계서(이 PRD 포함)
	•	설정 스키마 문서(키/옵션/기본값/예시)
	•	빌드/배포/운영/트러블슈팅 가이드
	•	테스트 케이스 목록과 자동화 스크립트

⸻

