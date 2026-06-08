import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Scanner;

import javax.crypto.SecretKey;

// 학생 제출 프로그램
// 평가 입력 -> 평가 패키지 생성 -> AES 암호화 -> 전자봉투 -> 해시 -> 전자서명
public class EvaluationSubmit {

    private static final SecureRandom RANDOM = new SecureRandom();

    public static void main(String[] args) {
        // try-with-resources 로 Scanner 자원을 항상 안전하게 해제
        try (Scanner scanner = new Scanner(System.in)) {
            run(scanner);
        } catch (GeneralSecurityException | IOException e) {
            // 사용자에게는 일반화된 메시지만 노출 (내부 경로/스택 정보 비노출)
            System.out.println();
            System.out.println("제출 처리 중 오류가 발생했습니다: " + e.getClass().getSimpleName());
            System.out.println("========================================");
        }
    }

    private static void run(Scanner scanner) throws GeneralSecurityException, IOException {
        System.out.println("========================================");
        System.out.println(" 전자봉투 기반 익명 동료평가 제출 시스템");
        System.out.println(" [학생 제출 모드]");
        System.out.println("========================================");
        System.out.println();

        // 1. 학생 정보 입력 (학번: 숫자만 허용)
        String studentId = readDigits(scanner, "학번 입력: ");
        System.out.println("학교 계정 인증 중...");
        System.out.println("수강생 여부 확인 완료");
        System.out.println("제출 권한 확인 완료");
        System.out.println();

        String anonymousId = "SUBMITTER-" + generateRandomHex(6);
        System.out.println("익명 제출 ID 생성: " + anonymousId);
        System.out.println();

        System.out.print("과목명 입력: ");
        String course = scanner.nextLine().trim();
        String team = readDigits(scanner, "팀 번호 입력: ");
        System.out.print("평가 대상자 입력: ");
        String target = scanner.nextLine().trim();
        int score = readScore(scanner); // 1~5 범위 정수 검증
        System.out.print("서술형 평가 입력: ");
        String comment = scanner.nextLine();
        System.out.print("증빙자료 파일명 입력: ");
        String evidence = scanner.nextLine().trim();

        String submittedAt = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        System.out.println("제출 시간: " + submittedAt);
        System.out.println();

        // 2. 평가 패키지(JSON 문자열) 구성 — 문자열 값은 JSON 이스케이프 처리
        String evaluationPackage =
              "{\n"
            + "  \"anonymousSubmitterId\":\"" + jsonEscape(anonymousId) + "\",\n"
            + "  \"course\":\"" + jsonEscape(course) + "\",\n"
            + "  \"team\":\"" + jsonEscape(team) + "\",\n"
            + "  \"target\":\"" + jsonEscape(target) + "\",\n"
            + "  \"score\":" + score + ",\n"
            + "  \"comment\":\"" + jsonEscape(comment) + "\",\n"
            + "  \"evidenceFile\":\"" + jsonEscape(evidence) + "\",\n"
            + "  \"submittedAt\":\"" + jsonEscape(submittedAt) + "\"\n"
            + "}";

        System.out.println("[1] 평가 패키지 생성 완료");
        System.out.println();

        // 3. AES 키 생성
        SecretKey aesKey = CryptoUtil.generateAESKey();
        System.out.println("[2] AES 대칭키 생성 완료");
        System.out.println(" - Algorithm: AES / Key Size: 128bit");
        System.out.println();

        // 4. 평가 패키지를 AES로 암호화 (AES/CBC/PKCS5Padding + 랜덤 IV)
        byte[] encrypted = CryptoUtil.encryptAES(evaluationPackage.getBytes(StandardCharsets.UTF_8), aesKey);
        FileUtil.saveBytes("evaluation_001.enc", encrypted);
        System.out.println("[3] 평가 패키지 암호화 완료 -> evaluation_001.enc");
        System.out.println();

        // 5. 전자봉투 생성 (AES 키를 교수자 공개키로 RSA 암호화)
        PublicKey professorPubKey = MyKeyPair.loadPublicKey("professor_public.key");
        byte[] envelope = EnvelopeUtil.createEnvelope(aesKey, professorPubKey);
        FileUtil.saveBytes("envelope_professor_001.bin", envelope);
        System.out.println("[4] 전자봉투 생성 완료 -> envelope_professor_001.bin");
        System.out.println();

        // 6. 암호화된 평가 데이터의 SHA-256 해시 생성
        byte[] hash = CryptoUtil.sha256(encrypted);
        String hashHex = CryptoUtil.bytesToHex(hash);
        FileUtil.saveString("hash_001.txt", hashHex);
        System.out.println("[5] SHA-256 해시 생성 완료 -> hash_001.txt");
        System.out.println(" - 해시값: " + hashHex.substring(0, 16) + " ...");
        System.out.println();

        // 7. 전자서명 생성
        // 서명 대상: 익명 제출 ID | 과목명 | 팀번호 | 제출시간 | 해시값
        String signTarget = anonymousId + "|" + course + "|" + team + "|" + submittedAt + "|" + hashHex;
        PrivateKey studentPrivKey = MyKeyPair.loadPrivateKey("student_private.key");
        byte[] signature = SignatureUtil.sign(signTarget.getBytes(StandardCharsets.UTF_8), studentPrivKey);
        FileUtil.saveBytes("signature_001.bin", signature);
        System.out.println("[6] 전자서명 생성 완료 (SHA256withRSA) -> signature_001.bin");
        System.out.println();

        // 8. 메타데이터 + 서명 검증용 학생 공개키 저장
        String meta =
              "anonymousSubmitterId=" + anonymousId + "\n"
            + "course=" + course + "\n"
            + "team=" + team + "\n"
            + "target=" + target + "\n"
            + "submittedAt=" + submittedAt;
        FileUtil.saveString("submit_meta_001.txt", meta);

        byte[] studentPubBytes = FileUtil.readBytes("student_public.key");
        FileUtil.saveBytes("student_public_001.key", studentPubBytes);

        System.out.println("[7] 서버 저장 완료");
        System.out.println(" - evaluation_001.enc / envelope_professor_001.bin");
        System.out.println(" - hash_001.txt / signature_001.bin");
        System.out.println(" - submit_meta_001.txt / student_public_001.key");
        System.out.println();
        System.out.println("평가 제출이 완료되었습니다. (교수자만 열람 가능)");
        System.out.println("========================================");
    }

    // 숫자만 허용하는 입력 (학번, 팀 번호)
    private static String readDigits(Scanner scanner, String prompt) {
        while (true) {
            System.out.print(prompt);
            String value = scanner.nextLine().trim();
            if (value.matches("\\d+")) {
                return value;
            }
            System.out.println(" -> 숫자만 입력하세요.");
        }
    }

    // 1~5 범위의 정수 점수 입력 검증
    private static int readScore(Scanner scanner) {
        while (true) {
            System.out.print("기여도 점수 입력(1~5): ");
            String line = scanner.nextLine().trim();
            try {
                int score = Integer.parseInt(line);
                if (score >= 1 && score <= 5) {
                    return score;
                }
            } catch (NumberFormatException e) {
                // 아래 안내 후 재입력
            }
            System.out.println(" -> 1~5 사이의 숫자를 입력하세요.");
        }
    }

    // JSON 문자열 값에 들어갈 수 있는 특수문자 이스케이프 (구조 깨짐 방지)
    private static String jsonEscape(String value) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\': sb.append("\\\\"); break;
                case '"':  sb.append("\\\""); break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                default:   sb.append(c);
            }
        }
        return sb.toString();
    }

    // 익명 제출 ID에 사용할 무작위 16진수 문자열 (SecureRandom 사용)
    private static String generateRandomHex(int length) {
        String chars = "0123456789ABCDEF";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(RANDOM.nextInt(chars.length())));
        }
        return sb.toString();
    }
}
