# Secure Coding Analysis Report

> 분석 기준: **Java Coding Guidelines (75 Recommendations for Reliable and Secure Programs)**
> 본 보고서의 모든 사례는 위 가이드라인의 *실제 규칙 번호·제목*에만 근거하여 작성하였다.

## 1. 보고서 정보

| 항목 | 내용 |
| --- | --- |
| 과목명 | 웹과 코드 보안 |
| 프로젝트명 | 전자봉투 기반 익명 동료평가 및 민감 평가 제출 시스템 |
| 작성자 | (학번 / 이름 기입) |
| 작성일 | YYYY-MM-DD |
| 언어 / 환경 | Java (JDK 21), Eclipse |
| 분석 대상 | `MyKeyPair`, `CryptoUtil`, `EnvelopeUtil`, `SignatureUtil`, `FileUtil`, `EvaluationSubmit`, `EvaluationRead` |
| 분석 방법 | *Java Coding Guidelines (75 Recommendations)* 의 규칙을 기준으로 한 수동 코드 리뷰 |

---

## 2. 분석 개요

### 2.1 시스템 개요
전자봉투(AES + RSA), 전자서명(SHA256withRSA), 무결성 해시(SHA-256)를 결합한 익명 동료평가 제출/열람 콘솔 프로그램이다.

### 2.2 적용한 Java Coding Guidelines 규칙 (PDF 실재 규칙만)

아래 규칙들은 *Java Coding Guidelines* 목차에 실제로 존재하는 항목이며, 본 프로젝트 코드에 직접 적용·수정하였다.

| 규칙 번호 | 규칙 제목 (원문) | 적용 사례 |
| --- | --- | --- |
| #12 | Do not use insecure or weak cryptographic algorithms | 사례 1, 사례 2 |
| #14 | Ensure that SecureRandom is properly seeded | 사례 3 |
| #11 | Do not use Object.equals() to compare cryptographic keys | 사례 4 |
| #4 | Ensure that security-sensitive methods are called with validated arguments | 사례 5 |
| #7 | Prevent code injection | 사례 6 |
| #43 | Use a try-with-resources statement to safely handle closeable resources | 사례 7 |
| #33 | Prefer user-defined exceptions over more general exception types | 사례 8 |
| #34 | Try to gracefully recover from system errors | 사례 9 |
| #16 | Avoid granting excess privileges | 사례 10 |
| #39 | Use meaningful symbolic constants to represent literal values in program logic | 사례 11 |
| #26 | Always provide feedback about the resulting value of a method | 부록 A |

---

## 3. 진단 사례 요약표

| 사례 | 적용 규칙 | 진단 항목 | 중요도 | 코드 위치 | 결과 |
| --- | --- | --- | --- | --- | --- |
| 1 | #12 | AES 운영 모드 미지정(ECB 기본값) | **상** | `CryptoUtil.java` | 수정 완료 |
| 2 | #12 | RSA 변환문자열 미지정(패딩 기본값 의존) | 중 | `EnvelopeUtil.java` | 수정 완료 |
| 3 | #14 | 익명 ID 생성에 `java.util.Random` 사용 | 중 | `EvaluationSubmit.java` | 수정 완료 |
| 4 | #11 | 해시 비교에 문자열 비교(`equalsIgnoreCase`) | 중 | `EvaluationRead`/`CryptoUtil` | 수정 완료 |
| 5 | #4 | 사용자 입력(점수/학번/팀번호) 검증 부재 | 중 | `EvaluationSubmit.java` | 수정 완료 |
| 6 | #7 | JSON 수동 조립으로 인한 인젝션 위험 | 중 | `EvaluationSubmit.java` | 수정 완료 |
| 7 | #43 | Scanner 자원을 try-with-resources 미사용 | 중 | `EvaluationSubmit`/`Read` | 수정 완료 |
| 8 | #33 | 광범위한 `throws Exception` 사용 | 중 | 전체 유틸 클래스 | 수정 완료 |
| 9 | #34 | 예외 전파로 인한 정보 노출/비정상 종료 | 중 | `EvaluationSubmit`/`Read` | 수정 완료 |
| 10 | #16 | 개인키 파일 접근 권한 과다 | 중 | `MyKeyPair.java` | 수정 완료 |
| 11 | #39 | 암호 알고리즘 문자열을 리터럴로 산재 | 하 | 다수 클래스 | 수정 완료 |

> 발표 대표 사례: **사례 1 (#12, AES ECB → CBC + 무작위 IV)**

---

## 4. 사례별 상세 분석

### 사례 1 — [#12] AES 운영 모드 미지정 (ECB 기본값 사용)

| 항목 | 내용 |
| --- | --- |
| 적용 규칙 | **#12. Do not use insecure or weak cryptographic algorithms** |
| 코드 위치 | `src/CryptoUtil.java` — `encryptAES()`, `decryptAES()` |
| 중요도 | **상 (High)** |

**보안 약점 / 취약점 이유**
`Cipher.getInstance("AES")` 처럼 운영 모드를 지정하지 않으면 JDK 기본 제공자에서 **ECB 모드**로 동작한다. ECB는 동일한 평문 블록이 항상 동일한 암호문 블록이 되어 데이터의 **패턴이 그대로 노출**된다. 평가 패키지는 정형화된 JSON이므로 반복 구조가 암호문에 드러나 기밀성이 약화된다(취약한 암호 사용 / 무작위 IV 부재).

**해결 방법**
운영 모드를 `AES/CBC/PKCS5Padding`으로 명시하고, 매 암호화마다 `SecureRandom`으로 16바이트 **IV를 새로 생성**하여 암호문 앞에 붙여 저장한다. 복호화 시 앞 16바이트를 IV로 분리한다.

**Before**
```java
Cipher cipher = Cipher.getInstance("AES");
cipher.init(Cipher.ENCRYPT_MODE, key);
return cipher.doFinal(data);
```
**After**
```java
byte[] iv = new byte[IV_SIZE];
new SecureRandom().nextBytes(iv);                 
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
byte[] cipherText = cipher.doFinal(data);

```
**검증**: 동일 평가 내용을 두 번 암호화하면 암호문이 서로 다름 + 제출→열람 왕복 정상.

---

### 사례 2 — [#12] RSA 변환문자열 미지정 (패딩 기본값 의존)

| 항목 | 내용 |
| --- | --- |
| 적용 규칙 | **#12. Do not use insecure or weak cryptographic algorithms** |
| 코드 위치 | `src/EnvelopeUtil.java` — `createEnvelope()`, `openEnvelope()` |
| 중요도 | 중 (Medium) |

**보안 약점 / 취약점 이유**
`Cipher.getInstance("RSA")` 는 패딩 방식을 제공자 기본값에 맡긴다. 실행 환경(Provider)에 따라 동작이 달라질 수 있고, 패딩이 명시되지 않아 안전성 검토가 어렵다. 암호 알고리즘은 모드·패딩까지 완전하게 지정해야 한다.

**해결 방법**
전자봉투 용도(AES 키 1블록 암호화)에 맞춰 `RSA/ECB/PKCS1Padding`으로 변환문자열을 완전하게 명시한다.

**Before**
```java
Cipher cipher = Cipher.getInstance("RSA");
```
**After**
```java
private static final String RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding";
Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
```
**검증**: 제출/열람 왕복 성공, 코드 리뷰 시 패딩 명시 확인.

---

### 사례 3 — [#14] 익명 ID 생성에 `java.util.Random` 사용

| 항목 | 내용 |
| --- | --- |
| 적용 규칙 | **#14. Ensure that SecureRandom is properly seeded** |
| 코드 위치 | `src/EvaluationSubmit.java` — `generateRandomHex()` |
| 중요도 | 중 (Medium) |

**보안 약점 / 취약점 이유**
익명 제출 ID 생성에 `java.util.Random`을 사용했다. `Random`은 예측 가능한 선형 합동 생성기로, 보안 식별자에 사용하면 ID가 **추측·재현**될 수 있어 익명성·고유성이 약화된다. 보안 맥락의 난수는 `SecureRandom`을 사용해야 한다.

**해결 방법**
`java.security.SecureRandom`으로 교체한다. (AES IV·RSA 키·전자서명에는 이미 `SecureRandom` 기반 API를 사용)

**Before**
```java
Random random = new Random();
sb.append(chars.charAt(random.nextInt(chars.length())));
```
**After**
```java
private static final SecureRandom RANDOM = new SecureRandom();
sb.append(chars.charAt(RANDOM.nextInt(chars.length())));
```
**검증**: 생성되는 익명 ID가 매번 달라지는지 확인 + 정상 제출.

---

### 사례 4 — [#11] 해시 비교에 문자열 비교 사용

| 항목 | 내용 |
| --- | --- |
| 적용 규칙 | **#11. Do not use Object.equals() to compare cryptographic keys** |
| 코드 위치 | `src/EvaluationRead.java` 해시 검증부 → `src/CryptoUtil.java` `verifyHash()` |
| 중요도 | 중 (Medium) |

**보안 약점 / 취약점 이유**
무결성 해시를 `savedHash.equalsIgnoreCase(...)` 로 비교했다. 문자열 비교는 첫 불일치 지점에서 즉시 반환하므로 비교 시간이 입력에 따라 달라져 **타이밍 사이드 채널**이 생길 수 있다. 규칙 #11은 키 등 **보안 민감 값을 `Object.equals`/일반 비교로 다루지 말 것**을 규정하며, 해시 비교에도 동일 원리가 적용된다. *(본 규칙은 원문상 "키" 비교를 다루지만, 보안 민감 바이트 비교에 전용 상수 시간 비교를 쓴다는 동일 원칙을 근거로 적용)*

**해결 방법**
`MessageDigest.isEqual()` 로 상수 시간(constant-time) 비교를 수행한다.

**Before**
```java
boolean hashOk = savedHash.equalsIgnoreCase(currentHashHex);
```
**After**
```java
byte[] expected = hexToBytes(expectedHex);
byte[] actual   = sha256(data);
return MessageDigest.isEqual(expected, actual);   // 상수 시간 비교
```
**검증**: 변조 데이터 입력 시 `해시 검증 결과: false` 후 열람 중단(실제 테스트 통과).

---

### 사례 5 — [#4] 사용자 입력 검증 부재

| 항목 | 내용 |
| --- | --- |
| 적용 규칙 | **#4. Ensure that security-sensitive methods are called with validated arguments** |
| 코드 위치 | `src/EvaluationSubmit.java` — `readScore()`, `readDigits()` |
| 중요도 | 중 (Medium) |

**보안 약점 / 취약점 이유**
점수(1~5), 학번, 팀번호를 형식·범위 검증 없이 그대로 사용해 평가 패키지 구성과 전자서명 대상에 투입했다. 검증되지 않은 인자가 보안 민감 처리(서명 대상 구성)로 흘러들어가 비정상·범위 밖 데이터가 그대로 저장·서명될 수 있다.

**해결 방법**
점수는 1~5 정수, 학번·팀번호는 숫자만 허용하는 검증 루프를 추가한다.

**Before**
```java
System.out.print("기여도 점수 입력(1~5): ");
String score = scanner.nextLine();   // 검증 없이 사용
```
**After**
```java
int score = Integer.parseInt(line.trim());
if (score >= 1 && score <= 5) return score;     // 범위 검증 후 재입력
// readDigits(): value.matches("\\d+") 인 경우만 허용
```
**검증**: 점수 0/6/"abc", 학번 "abc" 입력 시 재입력 요구되는지 경계값 테스트(통과).

---

### 사례 6 — [#7] JSON 수동 조립으로 인한 인젝션 위험

| 항목 | 내용 |
| --- | --- |
| 적용 규칙 | **#7. Prevent code injection** |
| 코드 위치 | `src/EvaluationSubmit.java` — 평가 패키지 구성부, `jsonEscape()` |
| 중요도 | 중 (Medium) |

**보안 약점 / 취약점 이유**
평가 패키지(JSON)를 사용자 입력으로 **문자열 직접 조립**했다. 서술형 평가 등에 큰따옴표(`"`)·역슬래시(`\`)·개행이 포함되면 JSON 구조가 깨지거나 임의 필드를 주입(JSON injection)할 수 있어 데이터 무결성·파싱이 위협받는다.

**해결 방법**
모든 문자열 값을 `jsonEscape()`로 이스케이프 처리한 뒤 삽입한다.

**Before**
```java
+ "  \"comment\":\"" + comment + "\",\n"     // 입력을 그대로 삽입
```
**After**
```java
+ "  \"comment\":\"" + jsonEscape(comment) + "\",\n"
// jsonEscape: \ " \n \r \t 등을 이스케이프
```
**검증**: 서술형에 `"핵심"` 처럼 큰따옴표 포함 입력 → 열람 시 `\"핵심\"` 으로 안전 출력(실제 테스트 통과).

---

### 사례 7 — [#43] Scanner 자원을 try-with-resources 미사용

| 항목 | 내용 |
| --- | --- |
| 적용 규칙 | **#43. Use a try-with-resources statement to safely handle closeable resources** |
| 코드 위치 | `src/EvaluationSubmit.java`, `src/EvaluationRead.java` — `main()` |
| 중요도 | 중 (Medium) |

**보안 약점 / 취약점 이유**
`Scanner`를 수동으로 `close()` 했다. 검증 실패로 중간에 `return` 하거나 예외가 발생하면 `close()`가 호출되지 않아 **자원 누수**가 발생할 수 있다.

**해결 방법**
`try-with-resources` 로 선언해 정상·예외 경로 모두에서 자동 해제되게 한다.

**Before**
```java
Scanner scanner = new Scanner(System.in);
// ... 중간 return / 예외 시 close 누락 가능 ...
scanner.close();
```
**After**
```java
try (Scanner scanner = new Scanner(System.in)) {
    run(scanner);
}
```
**검증**: 해시/서명 실패로 조기 종료해도 자원이 닫히는지 코드 경로 검토.

---

### 사례 8 — [#33] 광범위한 `throws Exception` 사용

| 항목 | 내용 |
| --- | --- |
| 적용 규칙 | **#33. Prefer user-defined exceptions over more general exception types** |
| 코드 위치 | `CryptoUtil`, `EnvelopeUtil`, `SignatureUtil`, `MyKeyPair`, `FileUtil` 등 |
| 중요도 | 중 (Medium) |

**보안 약점 / 취약점 이유**
모든 메서드가 `throws Exception` 으로 선언되어, 호출자가 어떤 예외가 발생하는지 알 수 없고 보안적으로 의미 있는 예외(키 손상·무결성 위반)와 단순 I/O 예외를 **구분·복구하지 못한다**. 지나치게 일반적인 예외 타입 사용은 규칙 #33이 지양하는 형태다.

**해결 방법**
`NoSuchAlgorithmException`, `InvalidKeyException`, `BadPaddingException`, `IOException` 등 **구체적 예외**를 명시 선언한다.

**Before**
```java
public static byte[] encryptAES(byte[] data, SecretKey key) throws Exception { ... }
```
**After**
```java
public static byte[] encryptAES(byte[] data, SecretKey key)
        throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
               InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException { ... }
```
**검증**: 컴파일러/IDE 인스펙션 + 의도적 예외 발생 테스트.

---

### 사례 9 — [#34] 예외 전파로 인한 정보 노출 / 비정상 종료

| 항목 | 내용 |
| --- | --- |
| 적용 규칙 | **#34. Try to gracefully recover from system errors** |
| 코드 위치 | `src/EvaluationSubmit.java`, `src/EvaluationRead.java` — `main()` |
| 중요도 | 중 (Medium) |

**보안 약점 / 취약점 이유**
`main(...) throws Exception` 으로 예외를 그대로 밖으로 던지면, 잘못된 키·손상 파일 등에서 **스택트레이스(내부 경로·구현 정보)가 노출**되고 프로그램이 비정상 종료된다(우아한 복구 실패).

**해결 방법**
`main`에서 `GeneralSecurityException`/`IOException`을 잡아 사용자에게는 일반화된 메시지(예외 클래스명 정도)만 보여 주고, 흐름을 우아하게 종료한다.

**Before**
```java
public static void main(String[] args) throws Exception {
    // 예외 시 스택트레이스 노출 + 비정상 종료
}
```
**After**
```java
try (Scanner scanner = new Scanner(System.in)) {
    run(scanner);
} catch (GeneralSecurityException | IOException e) {
    System.out.println("열람 처리 중 오류가 발생했습니다: " + e.getClass().getSimpleName());
}
```
**검증**: 잘못된 교수자 개인키 입력 시 스택트레이스 없이 `... BadPaddingException` 안전 메시지 출력(실제 테스트 통과).

---

### 사례 10 — [#16] 개인키 파일 접근 권한 과다

| 항목 | 내용 |
| --- | --- |
| 적용 규칙 | **#16. Avoid granting excess privileges** |
| 코드 위치 | `src/MyKeyPair.java` — `generateAndSave()`, `restrictToOwnerOnly()` |
| 중요도 | 중 (Medium) |

**보안 약점 / 취약점 이유**
RSA 개인키 파일(`*_private.key`)을 기본 권한(예: 644)으로 저장하면 같은 시스템의 **다른 사용자가 읽을 수 있다**(과도한 접근 권한). 개인키 노출 시 전자봉투 복호화·전자서명 위조가 가능하다.

**해결 방법**
키 생성 직후 POSIX 권한을 `rw-------`(600, 소유자 전용)으로 제한한다. POSIX 미지원 OS에서는 안전하게 건너뛴다.

**Before**
```java
FileUtil.saveBytes(privateKeyFile, pair.getPrivate().getEncoded());
// 권한 설정 없음
```
**After**
```java
FileUtil.saveBytes(privateKeyFile, pair.getPrivate().getEncoded());
restrictToOwnerOnly(privateKeyFile);   // PosixFilePermissions "rw-------"
```
**검증**: `ls -la *_private.key` 결과 `-rw-------` 확인(실제 확인됨).

---

### 사례 11 — [#39] 암호 알고리즘 문자열을 리터럴로 산재

| 항목 | 내용 |
| --- | --- |
| 적용 규칙 | **#39. Use meaningful symbolic constants to represent literal values in program logic** |
| 코드 위치 | `CryptoUtil`(`AES_TRANSFORMATION`,`AES_KEY_SIZE`,`IV_SIZE`), `EnvelopeUtil`(`RSA_TRANSFORMATION`), `SignatureUtil`(`SIGN_ALGORITHM`), `MyKeyPair`(`RSA_KEY_SIZE`) |
| 중요도 | 하 (Low) |

**보안 약점 / 취약점 이유**
`"AES/CBC/PKCS5Padding"`, `"RSA/ECB/PKCS1Padding"`, `128`, `16`, `"SHA256withRSA"` 같은 보안 관련 리터럴이 코드 곳곳에 흩어지면 의미 파악이 어렵고, 알고리즘을 바꿀 때 **일관되게 수정하지 못해 오류**가 생기기 쉽다.

**해결 방법**
의미 있는 명명 상수(`static final`)로 추출하여 한 곳에서 관리한다.

**Before**
```java
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
byte[] iv = new byte[16];
```
**After**
```java
private static final String AES_TRANSFORMATION = "AES/CBC/PKCS5Padding";
private static final int IV_SIZE = 16;
Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
byte[] iv = new byte[IV_SIZE];
```
**검증**: 컴파일 성공 + 알고리즘 변경 시 단일 지점 수정 가능.

---

## 5. 종합 결과

### 5.1 진단 통계

| 중요도 | 사례 수 | 수정 완료 |
| --- | --- | --- |
| 상 | 1 | 1 |
| 중 | 9 | 9 |
| 하 | 1 | 1 |
| **합계** | **11** | **11** |

### 5.2 발표 대표 사례
- **사례 1 (#12 — Do not use insecure or weak cryptographic algorithms)** 를 대표로 선정.
- 이유: 위험도가 가장 높고, 수업에서 배운 대칭 암호 원리와 직접 연결되며, ECB→CBC+IV 적용 전/후 암호문 차이를 시각적으로 보여줄 수 있다.

### 5.3 결론
- *Java Coding Guidelines* 의 실재 규칙 **11개 항목**(#4, #7, #11, #12, #14, #16, #33, #34, #39 + 부록 #26)을 적용하여 총 **11건**을 진단·수정하였다.
- 수정 후 제출→열람 왕복, 데이터 변조 탐지, 잘못된 키 처리 테스트를 모두 통과하였다.

---

## 부록 A. [#26] 파일 부분 읽기(read 반환값 미확인) — 관련 규칙 표기

> 아래는 가이드라인에 *정확히 일치하는 규칙은 없으나*, 가장 관련된 규칙 **#26. Always provide feedback about the resulting value of a method** 의 관점에서 함께 개선한 항목이다(`readBytes`가 항상 완전한 결과를 반환하도록 보장).

| 항목 | 내용 |
| --- | --- |
| 코드 위치 | `src/FileUtil.java` — `readBytes()` |
| 중요도 | 중 (Medium) |

**이유**: `fis.read(data)` 의 반환값(실제 읽은 바이트 수)을 확인하지 않으면 파일/스트림 상황에 따라 **일부만 읽혀** 복호화·무결성 검증이 비정상 동작할 수 있다.
**해결**: 끝까지 모두 읽는 `Files.readAllBytes` 사용.

**Before**
```java
FileInputStream fis = new FileInputStream(file);
byte[] data = new byte[(int) file.length()];
fis.read(data);   // 반환값 미확인 → 부분 읽기 가능
```
**After**
```java
return Files.readAllBytes(Paths.get(filename));
```

---

## 부록 B. 코딩 규칙 체크리스트 (Java Coding Guidelines 기준)

| 규칙 | 체크 항목 | 확인 |
| --- | --- | --- |
| #12 | 암호 운영 모드·패딩을 완전하게 명시했는가 (AES/CBC, RSA/ECB/PKCS1) | ☑ |
| #12 | AES IV가 매번 무작위로 생성되는가 | ☑ |
| #14 | 보안용 난수에 `SecureRandom`을 사용하는가 | ☑ |
| #11 | 보안 민감 값 비교가 상수 시간(`MessageDigest.isEqual`)인가 | ☑ |
| #4 | 사용자 입력의 형식·범위를 검증하는가 | ☑ |
| #7 | 사용자 입력을 구조 문자열(JSON)에 안전하게 삽입(이스케이프)하는가 | ☑ |
| #43 | 모든 자원이 try-with-resources로 닫히는가 | ☑ |
| #33 | 예외가 구체적 타입으로 선언되는가 | ☑ |
| #34 | 오류 시 우아하게 복구하고 민감 정보(스택)를 숨기는가 | ☑ |
| #16 | 개인키 파일 권한이 소유자 전용(`rw-------`)인가 | ☑ |
| #39 | 보안 관련 리터럴을 명명 상수로 관리하는가 | ☑ |
| #26 | 파일을 끝까지 모두 읽는가(`Files.readAllBytes`) | ☑ |
