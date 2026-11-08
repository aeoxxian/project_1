# Project 1: Asymmetric Cryptosystem (Alice-Bob Protocol)

Python 3 기반의 RSA, Diffie-Hellman(DH), AES-256-ECB 비대칭키/대칭키 통신 구현 프로젝트입니다.
표준 라이브러리만으로 동작하며, `pycryptodome` 또는 `cryptography`가 설치되어 있으면 AES 연산에 자동으로 사용합니다.

## 1. 파일 구조

- `common.py`: 네트워크 소켓 통신(JSON), 소수 판별, 생성자 검증, RSA/DH 핵심 수학 함수, 입력 포맷 호환 처리, 로그 파일 출력
- `aes_ecb.py`: AES-256-ECB 암호화 및 복호화 모듈 (PKCS#7 패딩, 순수 파이썬 폴백 포함)
- `alice.py`: 클라이언트(Alice) 실행 파일
- `bob.py`: 서버(Bob) 실행 파일
- `eve.py`: Protocol II(RSA) / Protocol III(DH) 도청 공격 (추가 과제 I, II)
- `run_tests.py`: 전체 알고리즘 및 프로토콜 자동화 테스트 스크립트

## 2. 실행 방법

서버(`bob.py`)를 먼저 실행한 후, 클라이언트(`alice.py`)를 실행합니다.

```bash
# 서버 실행 (5555 포트)
python bob.py -p 5555

# 프로토콜별 Alice 실행
python alice.py -a 127.0.0.1 -p 5555 --protocol rsakey   # Protocol I: RSA 키 검증
python alice.py -a 127.0.0.1 -p 5555 --protocol rsa      # Protocol II: RSA-AES 키 전달
python alice.py -a 127.0.0.1 -p 5555 --protocol dh       # Protocol III: DH 키 합의
```

공통 옵션:

- `-m, --message TEXT`: 전송할 메시지 (생략 시 터미널에서 입력, 기본값 Bob `hello` / Alice `world`)
- `-l, --log FILE`: 콘솔 출력을 파일에도 기록
- `--pubfmt int|base64`: DH 공개키 인코딩 (Alice는 기본 `auto`, 상대가 보낸 포맷을 따라감)
- `--timeout SEC`: 상대 응답 대기 시간 (0 = 무제한)
- Bob: `--forever` (연결을 계속 받음), `--connect` (TCP 클라이언트로 동작)
- Alice: `--listen` (TCP 서버로 동작)

### 예외 처리 테스트 (Protocol IV)
Bob 실행 시 오류 주입 옵션을 통해 예외 상황을 검증합니다.

```bash
# Protocol IV-1: p가 소수가 아닌 경우 (incorrect prime number)
python bob.py -p 5555 --fault prime

# Protocol IV-2: g가 생성자가 아닌 경우 (incorrect generator)
python bob.py -p 5555 --fault generator
```

### 도청 테스트 (Eve, 추가 과제 I·II)
```bash
python bob.py -p 5555 -m hello
python eve.py -p 6666 --bob-port 5555
python alice.py -a 127.0.0.1 -p 6666 --protocol rsa -m world   # 추가 과제 I  (RSA)
python alice.py -a 127.0.0.1 -p 6666 --protocol dh  -m world   # 추가 과제 II (DH)
```

### 자동 테스트 실행
```bash
python run_tests.py
```

## 3. 핵심 구현 내용

- **Protocol I**: RSA 키 생성 및 검증 ($p, q$ 소수성, 범위 $400 \sim 500$, $p \ne q$, $\gcd(e, \phi) = 1$, $e \cdot d \equiv 1 \pmod{\phi(n)}$ 검증)
- **Protocol II**: RSA 공개키로 32바이트 AES 키를 바이트 단위 암호화하여 전달 후 AES 통신
- **Protocol III**: Diffie-Hellman 공유 비밀($g^{ab} \bmod p$) 도출 후 `to_bytes(2, "big")` × 16 = 32바이트 AES 키 변환 및 대칭키 통신
- **Protocol IV**: DH 파라미터 유효성 검사 ($p$ 범위·소수성 검사, $g$ 생성자 검사 실패 시 `opcode: 3` 에러 반환 및 종료)
- **Eve (추가 과제 I)**: $n < 250{,}000$이므로 시행 나눗셈으로 소인수분해 → $d$ 복구 → AES 키 복호 → 양방향 메시지 해독
- **Eve (추가 과제 II)**: $p \le 500$이므로 이산로그 $a = \log_g A$를 브루트포스로 계산 → $B^a \bmod p$ → AES 키 복원 → 메시지 해독

## 4. 상호운용성 및 견고성

- **공개키 포맷**: `public` 필드는 정수와 Base64 문자열을 모두 받아들입니다.
- **암호화된 키 포맷**: `encrypted_key`(명세) 외에 `encryption` 필드도 인식하며, 값은 정수 리스트 / 문자열 리스트 / Base64(JSON 리스트) / Base64(고정폭 big-endian) 중 어느 형태든 디코딩합니다.
- **Bob 측 검증**: 수신한 DH 공개키가 $0 < A < p$인지 확인하고, 클라이언트가 `parameter`를 함께 보내면 Alice와 동일한 소수성·생성자 검사를 수행합니다. 잘못된 메시지에는 연결을 끊는 대신 `{"opcode": 3, "error": ...}`를 응답합니다.
- **AES 복호 실패**(키 불일치 등)도 `opcode: 3`으로 상대에게 알립니다.
- **JSON 스트림 처리**: 길이 접두사 없이 여러 메시지가 한 번에 도착하거나 나뉘어 도착해도 올바르게 분리합니다.

## 5. 참고 사항

- 소수 검사는 시행 나눗셈(Trial Division)을 기본으로 사용하며, 밀러-라빈(Miller-Rabin) 알고리즘을 통한 검증도 포함되어 있습니다.
- DH 생성자 검사는 $p-1$의 모든 소인수 $q$에 대해 $g^{(p-1)/q} \not\equiv 1 \pmod p$ 조건으로 판별합니다.
