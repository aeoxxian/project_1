# Project 1: Asymmetric Cryptosystem (Alice-Bob Protocol)

Python 3 기반의 RSA, Diffie-Hellman(DH), AES-256-ECB 비대칭키/대칭키 통신 구현 프로젝트입니다.

## 1. 파일 구조

- `common.py`: 네트워크 소켓 통신(JSON), 소수 판별, 생성자 검증, RSA/DH 핵심 수학 함수
- `aes_ecb.py`: AES-256-ECB 암호화 및 복호화 모듈
- `alice.py`: 클라이언트(Alice) 실행 파일
- `bob.py`: 서버(Bob) 실행 파일
- `eve.py`: Protocol II 도청 및 공격 테스트용 (보너스 과제)
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

### 예외 처리 테스트 (Protocol IV)
Bob 실행 시 오류 주입 옵션을 통해 예외 상황을 검증합니다.

```bash
# Protocol IV-1: p가 소수가 아닌 경우 (incorrect prime number)
python bob.py -p 5555 --fault prime

# Protocol IV-2: g가 생성자가 아닌 경우 (incorrect generator)
python bob.py -p 5555 --fault generator
```

### 도청 테스트 (Eve)
```bash
python bob.py -p 5555 -m hello
python eve.py -p 6666 --bob-port 5555
python alice.py -a 127.0.0.1 -p 6666 --protocol rsa -m world
```

### 단단한 테스트 실행
```bash
python run_tests.py
```

## 3. 핵심 구현 내용

- **Protocol I**: RSA 키 생성 및 검증 ($p, q$ 소수성, 범위 $400 \sim 500$, $e \cdot d \equiv 1 \pmod{\phi(n)}$ 검증)
- **Protocol II**: RSA 공개키로 32바이트 AES 키를 바이트 단위 암호화하여 전달 후 AES 통신
- **Protocol III**: Diffie-Hellman 공유 비밀($g^{ab} mod p$) 도출 후 32바이트 AES 키 변환 및 대칭키 통신
- **Protocol IV**: DH 파라미터 유효성 검사 ($p$ 소수성 검사, $g$ 생성자 검사 실패 시 `opcode: 3` 에러 반환 및 종료)
- **Eve Attack**: 소수가 작은 점을 이용한 RSA 소인수분해 기반 대칭키 탈취 및 메시지 복호화

## 4. 참고 사항

- 소수 검사는 시행 나눗셈(Trial Division)을 기본으로 사용하며, 밀러-라빈(Miller-Rabin) 알고리즘을 통한 검증도 포함되어 있습니다.
- DH 생성자 검사는 $p-1$의 모든 소인수 $q$에 대해 $g^{(p-1)/q} 
ot\equiv 1 \pmod p$ 조건으로 판별합니다.
- DH public key 포맷(int / Base64) 호환성 처리가 적용되어 있습니다.
