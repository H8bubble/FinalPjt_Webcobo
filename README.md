# FinalPjt_Webcobo

전자봉투 기반 익명 동료평가 및 민감 평가 제출 시스템

웹과 코드 보안 과목 기말 프로젝트. AES + RSA 전자봉투, SHA256withRSA 전자서명, SHA-256 무결성 해시를 결합한 Java 콘솔 프로그램이다.

## 클래스 구성 (`src/`)

| 클래스 | 역할 |
| --- | --- |
| `MyKeyPair.java` | RSA 2048bit 키쌍 생성/저장/복구 |
| `CryptoUtil.java` | AES 키 생성, AES 암/복호화, SHA-256 해시 |
| `EnvelopeUtil.java` | 전자봉투 생성 (RSA로 AES 키 암호화) / 복호화 |
| `SignatureUtil.java` | SHA256withRSA 전자서명 생성/검증 |
| `FileUtil.java` | 파일 byte[]/문자열 저장·읽기 |
| `EvaluationSubmit.java` | 학생 제출 콘솔 프로그램 (main) |
| `EvaluationRead.java` | 교수자 열람 콘솔 프로그램 (main) |

## 실행 방법

```bash
cd src
javac *.java

# 1) RSA 키쌍 생성 (최초 1회)
java MyKeyPair

# 2) 학생 제출 모드
java EvaluationSubmit

# 3) 교수자 열람 모드
java EvaluationRead
```

## 동작 흐름

1. **제출**: 평가 입력 → 평가 패키지 JSON → AES 암호화 → 전자봉투(AES 키를 교수자 공개키로 RSA 암호화) → SHA-256 해시 → 학생 개인키로 전자서명
2. **열람**: 전자봉투를 교수자 개인키로 복호화 → AES 키 복구 → 해시 검증 → 전자서명 검증 → AES로 평가 데이터 복호화 → 평가 내용 출력

## 실행 시 생성되는 파일

| 파일 | 설명 |
| --- | --- |
| `evaluation_001.enc` | AES로 암호화된 평가 패키지 |
| `envelope_professor_001.bin` | 교수자 공개키로 암호화된 AES 키 (전자봉투) |
| `hash_001.txt` | 암호화된 평가 데이터의 SHA-256 해시 |
| `signature_001.bin` | 학생 전자서명 |
| `submit_meta_001.txt` | 제출 메타데이터 (익명 ID, 과목명, 팀, 제출시간) |
| `submitted_records.txt` | 중복 제출 검증용 텍스트 파일 (학생 ID, 과목명, 팀, 평가 대상) |

## 보안 주의

- `*_private.key` 파일은 개인키이므로 **절대 저장소에 포함하지 않는다** (`.gitignore` 등록됨)
- 실행 결과로 생성되는 `.enc`, `.bin`, `.key`, `hash_*.txt`, `submit_meta_*.txt`, `submitted_records.txt` 도 모두 gitignore 처리됨
