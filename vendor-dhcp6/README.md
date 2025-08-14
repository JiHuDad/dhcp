# DHCPv6 Vendor Client

벤더 전용 옵션을 처리하는 특수한 DHCPv6 클라이언트입니다. ISC DHCP 기반으로 개발되었으며, Vendor-Specific Information (VSO, Option 17)을 통해 인증서 교환을 수행합니다.

## 개요

이 클라이언트는 다음과 같은 동작을 수행합니다:

1. **Solicit → Advertise**: 서버가 특정 조건을 만족하는지 확인
2. **Request**: VSO 내부에 서브옵션 71/72/73/74를 포함하여 전송
   - 71: SN_NUMBER (환경변수)
   - 72: SN_NUMBER의 RSA-SHA256 서명 (Base64)
   - 73: 요청용 인증서 (PEM 형식)
   - 74: 72와 동일한 서명 (복제)
3. **Reply**: VSO 내 서브옵션 77에서 인증서 체인을 추출하여 파일로 저장
   - 77: PEM 인증서 2개 (공백으로 구분)

## 주요 특징

- **설정 기반**: 모든 서브옵션 코드, 경로, 엔터프라이즈 번호를 TOML 설정으로 변경 가능
- **보안**: RSA-2048/SHA-256 서명, 민감정보 마스킹, 파일 권한 검증
- **로깅**: 레벨별 로깅, HEX 덤프 지원, 콘솔/파일 동시 출력
- **검증**: Advertise 게이트 검사, PEM 인증서 형식 검증
- **테스트**: 단위 테스트, 통합 테스트, 가짜 서버 데모

## 빌드 요구사항

- **OS**: Linux (glibc)
- **컴파일러**: GCC with C99 support
- **라이브러리**: OpenSSL (libcrypto, libssl)
- **권한**: Root (UDP/546 바인드, 네트워크 인터페이스 제어)

### 종속성 설치

```bash
# Ubuntu/Debian
sudo apt-get install build-essential libssl-dev

# CentOS/RHEL
sudo yum install gcc openssl-devel

# 테스트용 (선택사항)
pip3 install scapy
```

## 빌드 및 설치

```bash
# 1. 빌드
make

# 2. 설치 (선택사항)
sudo make install

# 3. 테스트
make test
```

## 설정

### 디렉터리 준비

```bash
sudo ./scripts/mkdirs.sh
```

### 키/인증서 생성

```bash
./scripts/gen_keypair.sh
```

### 설정 파일

`/etc/vendor/dhcp6-vendor.conf` (또는 `--config`로 지정):

```toml
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
private_key = "/etc/vendor/keys/client.key"
request_cert = "/etc/vendor/certs/request.pem"
reply_cert0 = "/var/lib/vendor-dhcp6/server0.pem"
reply_cert1 = "/var/lib/vendor-dhcp6/server1.pem"
reply_chain_bundle = "/var/lib/vendor-dhcp6/server_chain.pem"

[advertise_gate]
enabled = true
require_vendor = true
require_vendor_subopt = 90

[logging]
level = "info"
path = "/var/log/vendor-dhcp6.log"
hex_dump = false
```

## 사용법

### 기본 실행

```bash
# SN_NUMBER 환경변수 설정
export SN_NUMBER="ABC123456789"

# 클라이언트 실행
sudo ./vendor-dhclient --config /etc/vendor/dhcp6-vendor.conf --iface eth0
```

### 옵션

```bash
./vendor-dhclient [OPTIONS]

Options:
  -c, --config FILE    Configuration file
  -i, --iface IFACE    Network interface  
  -d, --dry-run        Don't send packets, just test VSO generation
  -v, --verbose        Verbose output (debug level)
  -h, --help           Show help
```

### 데모 실행

```bash
sudo ./scripts/run_demo.sh
```

## 종료 코드

- **0**: 성공
- **2**: 네트워크 타임아웃
- **3**: 설정/환경변수 오류
- **4**: 암호화 오류
- **5**: Reply 파싱/저장 실패
- **10**: Advertise 게이트 미충족

## 파일 구조

```
vendor-dhcp6/
├── src/                     # 소스 코드
│   ├── main.c              # 메인 애플리케이션
│   ├── cfg.c               # 설정 파서
│   ├── crypto.c            # 암호화 모듈
│   ├── log.c               # 로깅 시스템
│   ├── util.c              # 유틸리티
│   └── dhcp6_vendor.c      # VSO 처리 핵심 로직
├── include/                # 헤더 파일
├── conf/                   # 설정 파일 샘플
├── scripts/                # 설치/데모 스크립트
│   ├── mkdirs.sh          # 디렉터리 생성
│   ├── gen_keypair.sh     # 키/인증서 생성
│   └── run_demo.sh        # 데모 실행
├── tests/                  # 테스트
│   ├── unit/              # 단위 테스트
│   └── it/                # 통합 테스트 (가짜 서버)
└── Makefile               # 빌드 설정
```

## 보안 고려사항

### 파일 권한

- **프라이빗 키**: `/etc/vendor/keys/` (0700)
- **인증서**: `/etc/vendor/certs/` (0755)  
- **로그**: `/var/log/vendor-dhcp6.log` (0640)
- **수신 인증서**: `/var/lib/vendor-dhcp6/` (0750)

### 민감정보 처리

- SN_NUMBER 원문은 로그에 출력하지 않음 (앞 8자만 표시)
- RSA 서명 바이트는 메모리에서 즉시 클리어
- Base64 서명은 앞 8자만 로그에 표시

## 트러블슈팅

### 일반적인 오류

1. **"Failed to bind to port 546"**
   - Root 권한으로 실행하세요
   - 다른 DHCPv6 클라이언트가 실행 중인지 확인

2. **"Environment variable SN_NUMBER not set"**
   - `export SN_NUMBER="your_serial_number"` 실행

3. **"Private key file not found"**
   - `./scripts/gen_keypair.sh` 실행하여 키 생성

4. **"Advertise gate: Required sub-option 90 not found"**
   - 서버가 VSO를 올바르게 구성했는지 확인
   - `advertise_gate.enabled = false`로 임시 우회 가능

### 디버그 방법

```bash
# 1. Verbose 모드로 실행
sudo ./vendor-dhclient -c config.toml -i eth0 -v

# 2. Dry run으로 VSO 생성 테스트
./vendor-dhclient -c config.toml --dry-run

# 3. 로그 파일 확인
tail -f /var/log/vendor-dhcp6.log

# 4. 패킷 캡처 (별도 터미널)
sudo tcpdump -i eth0 -n port 546 or port 547
```

## 개발 및 확장

### 코드 구조

- **cfg.c**: TOML 설정 파싱, 기본값 설정
- **crypto.c**: OpenSSL 래퍼, RSA 서명, Base64 인코딩
- **dhcp6_vendor.c**: VSO TLV 조립/파싱, 인증서 처리
- **log.c**: 레벨별 로깅, HEX 덤프, 색상 출력
- **main.c**: DHCPv6 소켓 통신, 메시지 교환 로직

### 추가 기능 구현 가이드

1. **새 서브옵션 추가**: `build_request_vso()` 함수 수정
2. **다른 서명 알고리즘**: `crypto.c`에 ECDSA/Ed25519 지원 추가
3. **다중 인터페이스**: 소켓 생성 로직 확장
4. **인증서 검증**: `parse_reply_77_and_save()`에 OpenSSL 검증 로직 추가

## 라이선스

이 프로젝트는 ISC DHCP와 동일한 MPL 2.0 라이선스를 따릅니다.

## 지원

- **이슈 리포트**: 로그 파일과 설정 파일을 함께 제공
- **개발 문의**: 코드 변경 시 단위 테스트 실행 필수
- **운영 지원**: systemd 서비스 샘플 제공 예정