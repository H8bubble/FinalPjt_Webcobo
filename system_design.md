# 전자봉투 기반 익명 동료평가 및 민감 평가 제출 시스템 — 시스템 설계서

> 과목: 웹과 코드 보안 (Web & Code Security) / 기말 프로젝트
> 산출물 1 — 가상 시나리오 + 시스템 설계 문서

---

## 0. 가상 시나리오 (전자봉투 활용 시나리오)

### 0.1 배경

대학의 팀 프로젝트 수업에서는 학기 말에 **팀원 간 동료평가(peer evaluation)** 를 실시한다.
학생은 같은 팀원의 기여도를 점수와 서술형으로 평가하고, 필요하면 **증빙자료(첨부파일)** 를 함께 제출한다.
이 평가 결과는 성적에 반영되므로 매우 민감하다.

이때 다음과 같은 문제가 발생한다.

- 평가 대상자(팀원)가 "누가 나를 어떻게 평가했는지" 알게 되면 **보복·갈등**이 생길 수 있다 → **익명성** 필요
- 평가 내용이 서버 관리자나 조교에게 그대로 노출되면 안 된다 → **기밀성** 필요
- 제출 후 누군가 평가 내용을 몰래 바꾸면 안 된다 → **무결성** 필요
- 외부인이 수강생인 척 가짜 평가를 제출하면 안 된다 → **제출자 인증** 필요
- 증빙자료(이미지/문서)가 포함되면 데이터가 커진다 → **효율적인 암호화** 필요

### 0.2 왜 전자봉투(Digital Envelope)인가?

| 평가 데이터의 특징 | 전자봉투가 필요한 이유 |
| --- | --- |
| 평가 내용이 민감함 | 평가 대상자·서버 관리자에게 노출되면 안 된다. |
| 첨부파일이 포함될 수 있음 | 대용량 데이터는 공개키 암호화만으로 처리하기 비효율적이다. |
| 교수자만 열람해야 함 | AES 키를 교수자 공개키로 암호화해 권한 있는 사람만 열람 가능하게 한다. |
| 여러 열람 권한자가 있을 수 있음 | 같은 AES 키를 교수자·조교 공개키로 각각 암호화할 수 있다. |
| 서버에 저장되어야 함 | 서버는 데이터를 보관하지만 내용을 직접 볼 수 없다. |

**전자봉투**는 (1) 평가 데이터 자체는 빠른 **대칭키(AES)** 로 암호화하고,
(2) 그 AES 키만 수신자(교수자)의 **공개키(RSA)** 로 암호화해 함께 봉투에 담는 방식이다.
대칭키의 **속도**와 공개키의 **안전한 키 전달**이라는 두 장점을 동시에 얻는다.

### 0.3 등장 인물(역할)

| 역할 | 하는 일 | 가진 키 |
| --- | --- | --- |
| 학생(제출자) | 평가를 입력·암호화·서명하여 제출 | 학생 개인키(서명용) |
| 교수자(열람자) | 전자봉투를 열어 평가를 복호화·검증 | 교수자 개인키(복호화용) |
| 서버 | 암호문/봉투/해시/서명을 저장만 함 | (열람 불가) |

---

## 1. 보안 목표

| 보안 목표 | 설명 | 구현 수단 |
| --- | --- | --- |
| 기밀성 | 평가 내용은 권한 있는 교수자만 열람할 수 있어야 한다. | AES 암호화 + 전자봉투(RSA) |
| 무결성 | 제출된 평가가 이후에 조작되지 않았음을 확인할 수 있어야 한다. | SHA-256 해시 |
| 제출자 인증 | 실제 수강생이 제출했는지 확인할 수 있어야 한다. | SHA256withRSA 전자서명 |
| 익명성 | 평가 대상자는 누가 평가했는지 알 수 없어야 한다. | 익명 제출 ID 사용 |
| 접근 통제 | 교수자만 개인키로 전자봉투를 열 수 있다. | RSA 공개키/개인키 분리 |
| 효율성 | 첨부파일 포함 대용량도 효율적으로 암호화한다. | 대칭키(AES) 본문 암호화 |

---

## 2. 기능 요구사항 매핑 (PDF Functional Requirement)

| PDF 요구사항 | 구현 위치 |
| --- | --- |
| ① 파일에 저장된 문서에 대해 전자봉투를 생성 | `EvaluationSubmit` → `EnvelopeUtil.createEnvelope()` |
| ② 해당 문서의 전자봉투를 검증 | `EvaluationRead` → `EnvelopeUtil.openEnvelope()` + 해시/서명 검증 |
| ③ 전자서명용 비대칭키 생성/저장/복구 | `MyKeyPair.generateAndSave()` / `loadPublicKey()` / `loadPrivateKey()` |
| ③ 대칭키 생성/저장/복구 | `CryptoUtil.generateAESKey()` (생성) / 전자봉투에 담아 저장 / `CryptoUtil.bytesToAESKey()` (복구) |
| 최소 3개 이상의 기능별 클래스 | `MyKeyPair`, `CryptoUtil`, `EnvelopeUtil`, `SignatureUtil`, `FileUtil` (5개) |
| 사용자 인터페이스 | 콘솔(텍스트) UI — 7절 참고 |

---

## 3. 시스템 구성 요소 및 클래스 설계

### 3.1 구성 요소 개요

| 구성 요소 | 역할 |
| --- | --- |
| `EvaluationSubmit.java` | 학생이 평가 내용을 입력하고 제출하는 프로그램(main) |
| `EvaluationRead.java` | 교수자가 평가 내용을 복호화하고 검증하는 프로그램(main) |
| `MyKeyPair.java` | RSA 공개키/개인키를 생성·저장·복구 (Key Management) |
| `CryptoUtil.java` | AES 키 생성/복구, AES 암호화·복호화, SHA-256 해시 |
| `EnvelopeUtil.java` | AES 키를 교수자 공개키로 암호화(봉투 생성)/개인키로 복호화(봉투 열기) |
| `SignatureUtil.java` | 학생 개인키로 전자서명 생성, 학생 공개키로 검증 |
| `FileUtil.java` | 암호문/봉투/해시/서명/메타데이터 파일 저장·읽기 |

### 3.2 클래스 의존 관계

```
EvaluationSubmit ──┬─> CryptoUtil   (AES 키 생성, 암호화, 해시)
                   ├─> EnvelopeUtil ─> CryptoUtil (AES 키 복구)
                   ├─> SignatureUtil
                   ├─> MyKeyPair    (공개/개인키 로드)
                   └─> FileUtil     (파일 저장)

EvaluationRead   ──┴─> (동일한 유틸들을 검증·복호화 방향으로 사용)
```

---

### 3.3 클래스별 주요 메서드

#### MyKeyPair.java — Key Management (비대칭키)

RSA 2048bit 키쌍을 생성하고, X.509(공개키)/PKCS#8(개인키) 인코딩의 byte[]로 `.key` 파일에 저장한다.
복구 시 `X509EncodedKeySpec` / `PKCS8EncodedKeySpec` 으로 키 객체를 되살린다.

| 메서드 | 설명 |
| --- | --- |
| `generateAndSave(String pubFile, String privFile)` | RSA 2048bit 키쌍 생성(`SecureRandom` 기본 시드) 후 두 파일에 저장. 개인키 파일은 소유자 전용 권한(`rw-------`)으로 설정(가능한 OS에서). |
| `loadPublicKey(String file)` | `.key` 파일에서 공개키 복구 (`X509EncodedKeySpec`) |
| `loadPrivateKey(String file)` | `.key` 파일에서 개인키 복구 (`PKCS8EncodedKeySpec`) |
| `main(String[])` | 학생용·교수자용 키쌍을 한 번에 생성하는 실행 진입점 |

#### CryptoUtil.java — 대칭키 암호화 + 해시

AES 대칭키 암호화·복호화와 SHA-256 해시를 담당한다.
AES는 **CBC 모드 + PKCS5Padding** 을 사용하며, IV는 매 암호화마다 `SecureRandom` 으로 새로 만들어 **암호문 앞 16바이트**에 붙여 저장한다.

| 메서드 | 설명 |
| --- | --- |
| `generateAESKey()` | AES 128bit 대칭키 생성 (`KeyGenerator`, 내부적으로 `SecureRandom`) |
| `encryptAES(byte[] data, SecretKey key)` | `AES/CBC/PKCS5Padding` 암호화. 반환값: `[IV(16) ‖ 암호문]` |
| `decryptAES(byte[] data, SecretKey key)` | 앞 16바이트를 IV로 분리 후 복호화 |
| `bytesToAESKey(byte[] keyBytes)` | 봉투에서 복구한 byte[]로 AES `SecretKey` 객체 복구 (`SecretKeySpec`) |
| `sha256(byte[] data)` | SHA-256 해시값을 byte[]로 반환 |
| `bytesToHex(byte[] bytes)` | byte[] → 16진수 문자열 (해시 표시·저장용) |
| `verifyHash(byte[] data, String expectedHex)` | 데이터를 다시 해싱해 저장된 해시와 비교. `MessageDigest.isEqual()` 사용(상수 시간 비교) |

#### EnvelopeUtil.java — 전자봉투

평가 데이터는 AES로 암호화하고, 그 AES 키만 수신자 RSA 공개키로 암호화하여 전자봉투를 만든다.

| 메서드 | 설명 |
| --- | --- |
| `createEnvelope(SecretKey aesKey, PublicKey pub)` | AES 키를 수신자 공개키로 암호화하여 봉투(byte[]) 생성. `RSA/ECB/PKCS1Padding` 사용 |
| `openEnvelope(byte[] envelope, PrivateKey priv)` | 봉투를 수신자 개인키로 복호화 → AES 키 byte[] → `CryptoUtil.bytesToAESKey()` 로 `SecretKey` 복구하여 반환 |

> 같은 방식으로 동일한 AES 키를 조교·감사 담당자의 공개키로 추가 암호화하면, 여러 권한자가 각자의 개인키로 같은 평가를 열람할 수 있다(확장 가능).

#### SignatureUtil.java — 전자서명 (SHA256withRSA)

서명 대상은 평가 본문 전체가 아니라 `익명ID|과목명|팀번호|제출시간|해시값` 형태의 **검증 정보**로 구성한다.
→ 평가자 신원이 평가 본문에 직접 포함되지 않아 **익명성**이 유지된다.

| 메서드 | 설명 |
| --- | --- |
| `sign(byte[] data, PrivateKey priv)` | 데이터에 `SHA256withRSA` 전자서명 생성 |
| `verify(byte[] data, byte[] sig, PublicKey pub)` | 원본·서명·공개키로 서명 검증. true/false 반환 |

#### FileUtil.java — 파일 입출력

| 메서드 | 설명 |
| --- | --- |
| `saveBytes(String file, byte[] data)` | byte[]를 이진 파일(`.enc`, `.bin`, `.key`)로 저장 (try-with-resources) |
| `readBytes(String file)` | 이진 파일을 byte[]로 모두 읽기 (`readAllBytes`, 부분 읽기 방지) |
| `saveString(String file, String content)` | 문자열을 텍스트 파일(`.txt`)로 저장 |
| `readString(String file)` | 텍스트 파일을 문자열로 읽기 (줄바꿈 정리) |

---

## 4. 데이터 저장 구조

평가 하나가 제출될 때마다 아래 파일들이 생성된다(번호 `001` 예시).

```
src/
 ├─ evaluation_001.enc            AES로 암호화된 평가 패키지([IV‖암호문])
 ├─ envelope_professor_001.bin    교수자 공개키로 암호화된 AES 키(전자봉투)
 ├─ hash_001.txt                  암호화된 평가 데이터의 SHA-256 해시(16진수)
 ├─ signature_001.bin             제출자 전자서명
 ├─ submit_meta_001.txt           익명ID·과목명·팀번호·제출시간(평문 메타데이터)
 └─ student_public_001.key        제출자 서명 검증용 공개키
```

> 조교 등 추가 열람자가 있으면 `envelope_ta_001.bin` 처럼 봉투 파일을 하나 더 만들면 된다.

---

## 5. 주요 알고리즘 요약

| 기능 | 사용 알고리즘 | 목적 |
| --- | --- | --- |
| 평가 데이터 암호화 | AES/CBC/PKCS5Padding (128bit) + 랜덤 IV | 본문·첨부파일을 빠르게 암호화 |
| AES 키 암호화 | RSA/ECB/PKCS1Padding (2048bit) | 전자봉투 생성 |
| 전자서명 / 검증 | SHA256withRSA | 제출 권한 정보 서명·검증 |
| 무결성 해시 | SHA-256 | 암호문 변조 여부 확인 |
| 키 저장 | `.key` 파일 (X.509 / PKCS#8 byte[]) | 공개·개인키 저장/복구 |

---

## 6. 교수자 열람 흐름 — Key Recovery 포함

```
[교수자 열람 시작]
        │
        ▼
[1단계] 파일 로드
  evaluation_001.enc / envelope_professor_001.bin / hash_001.txt
  signature_001.bin / submit_meta_001.txt / student_public_001.key
        │
        ▼
[2단계] Key Recovery — 전자봉투 복호화 → AES 키 복구
  EnvelopeUtil.openEnvelope(envelope, professorPrivateKey)
    → RSA/ECB/PKCS1Padding 복호화 → AES 키 byte[]
    → CryptoUtil.bytesToAESKey(...) → SecretKey
  ※ 올바른 교수자 개인키가 없으면 이 단계에서 실패 → 열람 중단
        │
        ▼
[3단계] 무결성 검증 — 해시 비교 (MessageDigest.isEqual)
  불일치 시 "데이터 변경 가능성" 경고 → 열람 중단
        │
        ▼
[4단계] 제출자 인증 — 전자서명 검증 (SHA256withRSA)
  서명 대상: 익명ID|과목명|팀번호|제출시간|해시값
  실패 시 "유효하지 않은 서명" 경고 → 열람 중단
        │
        ▼
[5단계] AES 복호화 — [2단계]의 SecretKey로 평가 데이터 복원
        │
        ▼
[6단계] 평가 내용 출력 및 검증 결과 표시
```

> **Key Recovery 핵심**: 교수자 개인키 없이는 전자봉투를 열 수 없고, 따라서 AES 키도 얻을 수 없으므로 평가 데이터 복호화 자체가 불가능하다. 이것이 전자봉투가 제공하는 접근 통제이다.

---

## 7. 사용자 인터페이스 (콘솔 UI)

본 프로토타입은 **콘솔(텍스트) 기반 UI** 를 사용한다(PDF의 "콘솔창을 활용한 텍스트 입력" 항목).

- **제출 화면(`EvaluationSubmit`)**: 학번 인증 → 익명 ID 자동 생성 → 과목/팀/대상자/점수/서술형/증빙파일 입력 → 단계별([1]~[7]) 진행 로그 출력.
- **열람 화면(`EvaluationRead`)**: 평가 번호·교수자 개인키 파일 입력 → 봉투 복호화 → 해시·서명 검증 결과를 단계별로 출력 → 최종 평가 내용 표시.
- 각 단계마다 `====` 구분선과 `[n] ...` 형태의 진행 표시로 흐름을 한눈에 볼 수 있게 한다.

자세한 클래스 다이어그램과 화면 설명은 별도 문서 `class_and_ui.md` 참고.
