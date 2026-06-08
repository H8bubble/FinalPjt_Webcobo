# Secure Coding Analysis Report

## 1. 보고서 정보

| 항목 | 내용 |
| --- | --- |
| 과목명 | 웹과 코드 보안 |
| 프로젝트명 | 전자봉투 기반 익명 동료평가 및 민감 평가 제출 시스템 |
| 작성자 | (학번 / 이름 기입) |
| 작성일 | YYYY-MM-DD |
| 언어 / 환경 | Java (JDK), Eclipse |
| 분석 대상 | `MyKeyPair`, `CryptoUtil`, `EnvelopeUtil`, `SignatureUtil`, `FileUtil`, `EvaluationSubmit`, `EvaluationRead` |
| 분석 방법 | 수업 학습 내용 + *Java Coding Guidelines (75 Recommendations)* 기반 수동 코드 리뷰 |

---

## 2. 분석 개요

### 2.1 시스템 개요
본 시스템은 전자봉투(AES + RSA), 전자서명(SHA256withRSA), 무결성 해시(SHA-256)를 결합한 익명 동료평가 제출/열람 콘솔 프로그램이다.

### 2.2 분석 범위
- 키 생성/저장/복구 코드 (`MyKeyPair.java`)
- 대칭/비대칭 암호화 코드 (`CryptoUtil.java`, `EnvelopeUtil.java`)
- 전자서명 생성/검증 코드 (`SignatureUtil.java`)
- 파일 I/O 코드 (`FileUtil.java`)
- 사용자 입력 및 비즈니스 로직 (`EvaluationSubmit.java`, `EvaluationRead.java`)

### 2.3 적용 코딩 가이드라인 분류
보안 코딩 분류(A~G)와, 본 분석이 근거로 삼은 *Java Coding Guidelines* 권고 번호를 함께 표기한다.

| 분류 코드 | 분류명 | 본 프로젝트 관련성 | 관련 Java Coding Guidelines |
| --- | --- | --- | --- |
| A. 입력 데이터 검증 및 표현 | 사용자 입력값 검증, 인코딩 처리 | Scanner 입력 전반 | #4 검증된 인자, #6 출력 인코딩, #7 코드 인젝션 방지 |
| B. 보안 기능 | 암호화, 키 관리, 인증 | 핵심 영역 (전자봉투/전자서명) | #11 키 비교, #12 취약 암호 알고리즘 금지, #14 SecureRandom |
| C. 시간 및 상태 | 동시성, 세션 관리 | 낮음 (단일 콘솔) | - |
| D. 에러 처리 | 예외 처리 적절성, 정보 노출 | 전반 | #33 사용자 정의 예외 선호, #34 오류 복구 |
| E. 코드 오류 | 자원 해제, NULL 처리 | 파일 I/O, Scanner | #26 메서드 결과 피드백, #43 try-with-resources |
| F. 캡슐화 | 정보 은닉, 접근 제어 | 유틸 클래스 설계 | #24 접근성 최소화 |
| G. API 오용 | 위험 API 사용, 부적절 파라미터 | Cipher 운영 모드 등 | #12 안전한 알고리즘/모드 명시 |

---

## 3. 진단 사례 요약표

| 사례 번호 | 분류 | 진단 항목 | 위험도 | 적용 위치 | 처리 결과 |
| --- | --- | --- | --- | --- | --- |
| C-01 | B. 보안 기능 | AES 운영 모드 미지정(ECB 기본값 사용) | 상 | `CryptoUtil.java` | 수정 완료 |
| C-02 | E. 코드 오류 | 예외 발생 시 Scanner 자원 해제 누락 | 중 | `EvaluationRead/Submit.java` | 수정 완료 |
| C-03 | D. 에러 처리 | 광범위한 `throws Exception` 사용 | 중 | 전체 클래스 | 수정 완료 |
| C-04 | A. 입력 데이터 검증 | 점수/팀번호 등 사용자 입력 검증 부재 | 중 | `EvaluationSubmit.java` | 수정 완료 |
| C-05 | B. 보안 기능 | 개인키 파일 접근 권한 미설정 | 하 | `MyKeyPair.java` | 수정 완료 |
| C-06 | G. API 오용 | 해시 비교에 일반 문자열 비교(`equalsIgnoreCase`) 사용 | 중 | `EvaluationRead.java` | 수정 완료 |
| C-07 | B. 보안 기능 | RSA 변환문자열 미지정(Provider 기본값 의존) | 중 | `EnvelopeUtil.java` | 수정 완료 |
| C-08 | E. 코드 오류 | `FileInputStream.read()` 반환값 미확인(부분 읽기) | 중 | `FileUtil.java` | 수정 완료 |

> 사례별 상세 내용은 아래 4절의 양식표로 1개씩 작성한다.
> 발표 대표 사례는 위험도 '상'인 **C-01**을 사용한다.

---

## 4. 사례별 상세 분석 양식

> **양식 사용 방법**: 진단된 각 사례마다 아래 양식표를 1개씩 복사하여 작성한다.
> 발표 시에는 위험도가 높은 대표 사례 1개를 반드시 선택하여 시연한다.

---

### 4.1 [사례 C-01] AES 운영 모드 미지정 (ECB 기본값 사용)

| 항목 | 내용 |
| --- | --- |
| 사례 번호 | C-01 |
| 분류 | B. 보안 기능 — 취약한 암호화 알고리즘/모드 사용 |
| 적용 위치 | `CryptoUtil.java`, `encryptAES()` / `decryptAES()` 메서드 |
| 위험도 | **상** |
| 진단 내용 | `Cipher.getInstance("AES")`는 JDK 기본 공급자에서 `AES/ECB/PKCS5Padding`으로 동작한다. ECB 모드는 동일한 평문 블록이 동일한 암호문 블록을 만들어 패턴이 노출되므로 사용이 권장되지 않는다. |
| 보안 위협 | 평가 패키지가 유사한 형식의 JSON이라 ECB 패턴 분석 시 일부 구조 추론이 가능. 기밀성 약화. |
| 개선 방안 | CBC 또는 GCM 모드와 임의 IV(Initialization Vector)를 사용한다. IV는 암호문 앞에 함께 저장한다. |
| 위반 코드 (Before) | ```java\nCipher cipher = Cipher.getInstance("AES");\ncipher.init(Cipher.ENCRYPT_MODE, key);\nreturn cipher.doFinal(data);\n``` |
| 수정 코드 (After) | ```java\nbyte[] iv = new byte[16];\nnew SecureRandom().nextBytes(iv);\nCipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");\ncipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));\nbyte[] enc = cipher.doFinal(data);\n// iv + enc 를 함께 저장\n``` |
| 적용 효과 | 동일 평문이라도 매번 다른 암호문이 생성되어 ECB 패턴 노출 문제 제거. 평가 데이터 기밀성 강화. |
| 검증 방법 | 동일한 평가 내용을 두 번 암호화한 결과의 hex 출력이 서로 다른지 비교 |

---

### 4.2 [사례 C-02] 예외 발생 시 Scanner 자원 해제 누락

| 항목 | 내용 |
| --- | --- |
| 사례 번호 | C-02 |
| 분류 | E. 코드 오류 — 부적절한 자원 해제 (Resource Leak) |
| 적용 위치 | `EvaluationRead.java`, `main()` |
| 위험도 | **중** |
| 진단 내용 | 해시 검증 실패 또는 서명 검증 실패 시 `return` 으로 종료하지만, 중간 단계에서 예외가 발생하면 `scanner.close()`가 호출되지 않아 자원이 해제되지 않을 가능성이 있다. |
| 보안 위협 | 자원 누수로 인한 가용성 저하, 장기 실행 시스템으로 확장될 경우 핸들 고갈 가능. |
| 개선 방안 | `try-with-resources` 구문으로 자동 해제 보장. |
| 위반 코드 (Before) | ```java\nScanner scanner = new Scanner(System.in);\n// ... 처리 ...\nif (!hashOk) { scanner.close(); return; }\nscanner.close();\n``` |
| 수정 코드 (After) | ```java\ntry (Scanner scanner = new Scanner(System.in)) {\n    // ... 처리 ...\n    if (!hashOk) return;\n    // ... 정상 흐름 ...\n}\n``` |
| 적용 효과 | 예외 발생/중간 종료 여부와 무관하게 Scanner가 항상 정상적으로 닫힘. |
| 검증 방법 | 코드 경로 검토 + 정적 분석(예: SpotBugs `OS_OPEN_STREAM`) |

---

### 4.3 [사례 C-03] 광범위한 `throws Exception` 사용

| 항목 | 내용 |
| --- | --- |
| 사례 번호 | C-03 |
| 분류 | D. 에러 처리 — 부적절한 예외 처리 |
| 적용 위치 | 전체 클래스의 모든 메서드 시그니처 |
| 위험도 | **중** |
| 진단 내용 | 모든 메서드가 `throws Exception` 으로 선언되어 있어 어떤 예외가 발생할 수 있는지 호출자가 알 수 없고, 적절한 복구 처리도 어렵다. |
| 보안 위협 | 예외 메시지를 그대로 출력할 경우 내부 경로/스택 정보 유출 가능. 보안적으로 의미 있는 예외(키 손상, 무결성 위반)와 단순 I/O 예외를 구분하지 못함. |
| 개선 방안 | 구체적인 예외(`NoSuchAlgorithmException`, `InvalidKeyException`, `IOException`)를 명시. 사용자에게는 일반화된 메시지를, 로그에는 상세 메시지를 분리하여 출력. |
| 위반 코드 (Before) | ```java\npublic static byte[] encryptAES(byte[] data, SecretKey key) throws Exception { ... }\n``` |
| 수정 코드 (After) | ```java\npublic static byte[] encryptAES(byte[] data, SecretKey key)\n        throws NoSuchAlgorithmException, NoSuchPaddingException,\n               InvalidKeyException, IllegalBlockSizeException, BadPaddingException { ... }\n``` |
| 적용 효과 | 호출자가 처리해야 할 예외를 명확히 알 수 있고, 위협 유형별 분기 처리 가능. |
| 검증 방법 | 컴파일러 경고/IDE 인스펙션 + 의도적 예외 발생 테스트 |

---

### 4.4 [사례 C-04] 사용자 입력 검증 부재

| 항목 | 내용 |
| --- | --- |
| 사례 번호 | C-04 |
| 분류 | A. 입력 데이터 검증 및 표현 |
| 적용 위치 | `EvaluationSubmit.java`, 학생 정보/평가 점수/팀번호 입력부 |
| 위험도 | **중** |
| 진단 내용 | 점수(1~5), 팀번호, 학번 입력값을 그대로 사용하며 형식/범위 검증이 없다. 또한 JSON 문자열을 수동 조립하므로 큰따옴표, 백슬래시가 포함되면 JSON 구조가 깨질 수 있다. |
| 보안 위협 | JSON 인젝션 유사 문제, 정수 파싱 오류, 비정상적인 평가 데이터 제출. |
| 개선 방안 | (1) 점수는 1~5 범위 정수로 검증, (2) 학번은 숫자만 허용, (3) 서술형 입력은 큰따옴표/제어문자 이스케이프 처리. |
| 위반 코드 (Before) | ```java\nSystem.out.print("기여도 점수 입력(1~5): ");\nString score = scanner.nextLine();\n// 그대로 JSON에 삽입\n``` |
| 수정 코드 (After) | ```java\nint score;\nwhile (true) {\n    try {\n        score = Integer.parseInt(scanner.nextLine().trim());\n        if (score >= 1 && score <= 5) break;\n    } catch (NumberFormatException e) { /* 안내 후 재입력 */ }\n    System.out.print("1~5 사이 숫자를 입력하세요: ");\n}\n// 서술형: 큰따옴표/백슬래시 이스케이프\nString safeComment = comment.replace("\\\\", "\\\\\\\\").replace("\\"", "\\\\\\"");\n``` |
| 적용 효과 | 부정확한 데이터로 인한 시스템 오류 방지, JSON 구조 안정성 확보. |
| 검증 방법 | 경계값 테스트: 점수 0, 6, -1, "abc", 큰따옴표 포함 서술형 입력 |

---

### 4.5 [사례 C-05] 개인키 파일 접근 권한 미설정

| 항목 | 내용 |
| --- | --- |
| 사례 번호 | C-05 |
| 분류 | B. 보안 기능 — 키 보관/관리 |
| 적용 위치 | `MyKeyPair.java`, `generateAndSave()` |
| 위험도 | **하** |
| 진단 내용 | RSA 개인키 파일(`*_private.key`)을 일반 권한(644)으로 저장한다. 같은 시스템의 다른 사용자가 읽을 수 있다. |
| 보안 위협 | 개인키 노출 시 전자봉투 복호화 및 전자서명 위조 가능. |
| 개선 방안 | 파일 생성 직후 `Files.setPosixFilePermissions`로 소유자 전용(600)으로 설정. 가능하면 키스토어(JKS/PKCS12) 사용. |
| 위반 코드 (Before) | ```java\nFileUtil.saveBytes(privateKeyFile, pair.getPrivate().getEncoded());\n``` |
| 수정 코드 (After) | ```java\nFileUtil.saveBytes(privateKeyFile, pair.getPrivate().getEncoded());\nSet<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");\nFiles.setPosixFilePermissions(Paths.get(privateKeyFile), perms);\n``` |
| 적용 효과 | 다중 사용자 환경에서 개인키 파일이 다른 사용자에게 노출되지 않음. |
| 검증 방법 | `ls -la *_private.key` 로 권한이 `-rw-------` 인지 확인 |
| 처리 결과 | **수정 완료** — `MyKeyPair.restrictToOwnerOnly()` 추가, 키 생성 후 권한 `rw-------` 확인됨. POSIX 미지원 OS에서는 안전하게 건너뜀. |

---

### 4.6 [사례 C-06] 해시 비교에 일반 문자열 비교 사용

| 항목 | 내용 |
| --- | --- |
| 사례 번호 | C-06 |
| 분류 | G. API 오용 — 보안 민감 비교에 부적절한 메서드 사용 |
| 적용 위치 | `EvaluationRead.java` 해시 검증부 → `CryptoUtil.verifyHash()` |
| 위험도 | **중** |
| 진단 내용 | 무결성 해시 비교를 `savedHash.equalsIgnoreCase(currentHashHex)` 로 수행했다. 문자열 비교는 첫 불일치 지점에서 즉시 반환하므로 비교 시간이 입력에 따라 달라진다(타이밍 사이드 채널). *Java Coding Guidelines* #11은 보안 민감 값(키·해시·MAC) 비교에 단순 `equals` 사용을 지양할 것을 권고한다. |
| 보안 위협 | 이론적으로 비교 시간 차이를 이용해 해시값을 한 바이트씩 추측하는 타이밍 공격이 가능. |
| 개선 방안 | `MessageDigest.isEqual()` 을 사용해 상수 시간(constant-time) 비교를 수행한다. |
| 위반 코드 (Before) | ```java\nboolean hashOk = savedHash.equalsIgnoreCase(currentHashHex);\n``` |
| 수정 코드 (After) | ```java\n// CryptoUtil.verifyHash\nbyte[] expected = hexToBytes(expectedHex);\nbyte[] actual = sha256(data);\nreturn MessageDigest.isEqual(expected, actual);\n``` |
| 적용 효과 | 비교 시간이 입력값과 무관해져 타이밍 사이드 채널이 제거됨. |
| 검증 방법 | 변조 데이터 입력 시 `해시 검증 결과: false` 출력 후 열람 중단되는지 확인(실제 테스트 통과). |

---

### 4.7 [사례 C-07] RSA 변환문자열 미지정 (Provider 기본값 의존)

| 항목 | 내용 |
| --- | --- |
| 사례 번호 | C-07 |
| 분류 | B. 보안 기능 — 암호 알고리즘/모드 명시 (*Java Coding Guidelines* #12) |
| 적용 위치 | `EnvelopeUtil.java`, `createEnvelope()` / `openEnvelope()` |
| 위험도 | **중** |
| 진단 내용 | `Cipher.getInstance("RSA")` 처럼 알고리즘만 지정하면 패딩 방식이 Provider 기본값에 의존한다. 실행 환경(Provider)에 따라 동작이 달라질 수 있고, 패딩이 명확하지 않으면 안전성 검토가 어렵다. |
| 보안 위협 | 환경 의존적 동작, 향후 취약한 패딩으로 묵시적 전환될 위험. |
| 개선 방안 | 변환문자열을 `RSA/ECB/PKCS1Padding` 으로 완전하게 명시한다(AES 키 1블록 암호화 용도). |
| 위반 코드 (Before) | ```java\nCipher cipher = Cipher.getInstance("RSA");\n``` |
| 수정 코드 (After) | ```java\nprivate static final String RSA_TRANSFORMATION = \"RSA/ECB/PKCS1Padding\";\nCipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);\n``` |
| 적용 효과 | 실행 환경과 무관하게 동일·명시적 동작 보장, 코드 리뷰 시 패딩 확인 용이. |
| 검증 방법 | 제출/열람 왕복(round-trip) 성공 확인. |

---

### 4.8 [사례 C-08] 파일 부분 읽기 (read 반환값 미확인)

| 항목 | 내용 |
| --- | --- |
| 사례 번호 | C-08 |
| 분류 | E. 코드 오류 — 메서드 반환값 미확인 (*Java Coding Guidelines* #26) |
| 적용 위치 | `FileUtil.java`, `readBytes()` |
| 위험도 | **중** |
| 진단 내용 | `fis.read(data)` 의 반환값(실제 읽은 바이트 수)을 확인하지 않았다. 파일이 크거나 스트림이 분할되면 버퍼 일부만 채워질 수 있어, 봉투/암호문이 부분적으로만 읽혀 복호화·검증이 비정상 동작할 수 있다. |
| 보안 위협 | 무결성 검증 우회/오작동, 데이터 손상으로 인한 가용성 저하. |
| 개선 방안 | 끝까지 모두 읽는 API(`Files.readAllBytes`)를 사용한다. |
| 위반 코드 (Before) | ```java\nFileInputStream fis = new FileInputStream(file);\nbyte[] data = new byte[(int) file.length()];\nfis.read(data); // 반환값 미확인\n``` |
| 수정 코드 (After) | ```java\nreturn Files.readAllBytes(Paths.get(filename));\n``` |
| 적용 효과 | 파일 전체가 항상 정확히 읽혀 무결성 검증이 신뢰 가능해짐. |
| 검증 방법 | 정상 왕복 동작 + 코드 리뷰. |

---

### 4.X [사례 C-XX] (제목)

| 항목 | 내용 |
| --- | --- |
| 사례 번호 |  |
| 분류 |  |
| 적용 위치 |  |
| 위험도 | 상 / 중 / 하 |
| 진단 내용 |  |
| 보안 위협 |  |
| 개선 방안 |  |
| 위반 코드 (Before) | ```java\n\n``` |
| 수정 코드 (After) | ```java\n\n``` |
| 적용 효과 |  |
| 검증 방법 |  |

> 위 빈 양식표를 추가 사례마다 복사하여 작성한다.

---

## 5. 종합 결과

### 5.1 진단 결과 통계

| 위험도 | 사례 수 | 처리 완료 | 미처리 |
| --- | --- | --- | --- |
| 상 | 1 | 1 | 0 |
| 중 | 6 | 6 | 0 |
| 하 | 1 | 1 | 0 |
| **합계** | **8** | **8** | **0** |

### 5.2 발표 대표 사례
> 발표 시에는 **사례 C-01 (AES 운영 모드 미지정)** 을 대표 사례로 선택하여 시연한다.
> 이유: 위험도가 가장 높고, 수업에서 학습한 대칭 암호화 원리와 직접적으로 연결되며, 수정 전/후의 암호문 차이를 시각적으로 보여줄 수 있어 발표 효과가 크다.

### 5.3 결론
- 본 분석을 통해 총 **8건**의 보안 코딩 사례를 발견하고 **8건 모두 수정 적용**하였다.
- 핵심 보안 기능(전자봉투, 전자서명, 무결성 해시)은 정상 동작하며, 수정 후 제출→열람 왕복 테스트와 변조·잘못된 키에 대한 부정 경로 테스트를 모두 통과하였다.
- 가장 중요한 개선은 **AES 운영 모드 명시(C-01)** 로, 기본값 ECB 대신 `AES/CBC/PKCS5Padding` + 무작위 IV를 적용하여 평가 데이터 기밀성을 강화하였다.
- 본 보고서는 *Java Coding Guidelines (75 Recommendations)* 의 권고(#11, #12, #14, #26, #43 등)를 기준으로 사례를 정리하였다.

---

## 부록 A. 코딩 규칙 체크리스트

| 체크 항목 | 확인 |
| --- | --- |
| AES/RSA 알고리즘과 키 길이가 권고치 이상인가 (AES-128, RSA-2048) | ☑ |
| 암호 운영 모드(CBC/GCM 등)가 명시되었는가 (AES/CBC, RSA/ECB/PKCS1) | ☑ |
| IV(Initialization Vector)는 매번 무작위로 생성되는가 | ☑ |
| 개인키 파일 권한이 소유자 전용(`rw-------`)으로 설정되는가 | ☑ |
| 모든 자원(Scanner, Stream)이 try-with-resources/Files API로 닫히는가 | ☑ |
| 예외가 구체적으로 선언/처리되는가 | ☑ |
| 사용자 입력의 형식과 범위를 검증하는가 (학번·팀번호 숫자, 점수 1~5) | ☑ |
| 예외 메시지에 민감 정보(스택/경로)가 노출되지 않는가 | ☑ |
| 해시 비교가 상수 시간(constant-time)으로 수행되는가 (`MessageDigest.isEqual`) | ☑ |
| 파일을 끝까지 모두 읽는가 (`Files.readAllBytes`) | ☑ |
