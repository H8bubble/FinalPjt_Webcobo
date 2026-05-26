import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.SecretKey;

// 학생 제출 프로그램
// 평가 입력 -> 평가 패키지 생성 -> AES 암호화 -> 전자봉투 -> 해시 -> 전자서명
public class EvaluationSubmit {

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        System.out.println("========================================");
        System.out.println(" 전자봉투 기반 익명 동료평가 제출 시스템");
        System.out.println(" [학생 제출 모드]");
        System.out.println("========================================");
        System.out.println();

        // 1. 학생 정보 입력
        System.out.print("학번 입력: ");
        String studentId = scanner.nextLine();
        System.out.println("학교 계정 인증 중...");
        System.out.println("수강생 여부 확인 완료");
        System.out.println("제출 권한 확인 완료");
        System.out.println();

        String anonymousId = "SUBMITTER-" + generateRandomHex(6);
        System.out.println("익명 제출 ID 생성: " + anonymousId);
        System.out.println();

        System.out.print("과목명 입력: ");
        String course = scanner.nextLine();
        System.out.print("팀 번호 입력: ");
        String team = scanner.nextLine();
        System.out.print("평가 대상자 입력: ");
        String target = scanner.nextLine();
        System.out.print("기여도 점수 입력(1~5): ");
        String score = scanner.nextLine();
        System.out.println("서술형 평가 입력:");
        String comment = scanner.nextLine();
        System.out.print("증빙자료 파일명 입력: ");
        String evidence = scanner.nextLine();

        String submittedAt = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        System.out.println("제출 시간: " + submittedAt);
        System.out.println();

        // 2. 평가 패키지 (JSON 문자열) 구성
        String evaluationPackage =
              "{\n"
            + "  \"anonymousSubmitterId\":\"" + anonymousId + "\",\n"
            + "  \"course\":\"" + course + "\",\n"
            + "  \"team\":\"" + team + "\",\n"
            + "  \"target\":\"" + target + "\",\n"
            + "  \"score\":" + score + ",\n"
            + "  \"comment\":\"" + comment + "\",\n"
            + "  \"evidenceFile\":\"" + evidence + "\",\n"
            + "  \"submittedAt\":\"" + submittedAt + "\"\n"
            + "}";

        System.out.println("[1] 평가 패키지 생성 완료");
        System.out.println();

        // 3. AES 키 생성
        SecretKey aesKey = CryptoUtil.generateAESKey();
        System.out.println("[2] AES 대칭키 생성 완료");
        System.out.println(" - Algorithm: AES");
        System.out.println(" - Key Size: 128bit");
        System.out.println();

        // 4. 평가 패키지를 AES로 암호화
        byte[] encrypted = CryptoUtil.encryptAES(evaluationPackage.getBytes("UTF-8"), aesKey);
        FileUtil.saveBytes("evaluation_001.enc", encrypted);
        System.out.println("[3] 평가 패키지 암호화 완료");
        System.out.println(" - 생성 파일: evaluation_001.enc");
        System.out.println();

        // 5. 전자봉투 생성 (AES 키를 교수자 공개키로 RSA 암호화)
        PublicKey professorPubKey = MyKeyPair.loadPublicKey("professor_public.key");
        byte[] envelope = EnvelopeUtil.createEnvelope(aesKey, professorPubKey);
        FileUtil.saveBytes("envelope_professor_001.bin", envelope);
        System.out.println("[4] 전자봉투 생성 완료");
        System.out.println(" - 교수자 공개키 파일: professor_public.key");
        System.out.println(" - 생성 파일: envelope_professor_001.bin");
        System.out.println();

        // 6. 암호화된 평가 데이터의 SHA-256 해시 생성
        byte[] hash = CryptoUtil.sha256(encrypted);
        String hashHex = CryptoUtil.bytesToHex(hash);
        FileUtil.saveString("hash_001.txt", hashHex);
        System.out.println("[5] SHA-256 해시 생성 완료");
        System.out.println(" - 생성 파일: hash_001.txt");
        System.out.println(" - 해시값: " + hashHex.substring(0, 16) + " ...");
        System.out.println();

        // 7. 전자서명 생성
        // 서명 대상: 익명 제출 ID + 과목명 + 팀번호 + 제출시간 + 해시값
        String signTarget = anonymousId + "|" + course + "|" + team + "|" + submittedAt + "|" + hashHex;
        PrivateKey studentPrivKey = MyKeyPair.loadPrivateKey("student_private.key");
        byte[] signature = SignatureUtil.sign(signTarget.getBytes("UTF-8"), studentPrivKey);
        FileUtil.saveBytes("signature_001.bin", signature);
        System.out.println("[6] 전자서명 생성 완료");
        System.out.println(" - 서명 알고리즘: SHA256withRSA");
        System.out.println(" - 개인키 파일: student_private.key");
        System.out.println(" - 생성된 서명 정보: " + signature.length + " bytes");
        System.out.println(" - 생성 파일: signature_001.bin");
        System.out.println();

        // 8. 메타데이터 저장 (검증 시 필요한 평문 정보)
        String meta =
              "anonymousSubmitterId=" + anonymousId + "\n"
            + "course=" + course + "\n"
            + "team=" + team + "\n"
            + "submittedAt=" + submittedAt;
        FileUtil.saveString("submit_meta_001.txt", meta);

        System.out.println("[7] 서버 저장 완료");
        System.out.println(" - evaluation_001.enc");
        System.out.println(" - envelope_professor_001.bin");
        System.out.println(" - hash_001.txt");
        System.out.println(" - signature_001.bin");
        System.out.println(" - submit_meta_001.txt");
        System.out.println();
        System.out.println("평가 제출이 완료되었습니다.");
        System.out.println("평가 내용은 교수자만 열람할 수 있습니다.");
        System.out.println("========================================");

        scanner.close();
    }

    // 익명 제출 ID에 사용할 무작위 16진수 문자열
    private static String generateRandomHex(int length) {
        Random random = new Random();
        StringBuilder sb = new StringBuilder();
        String chars = "0123456789ABCDEF";
        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }
        return sb.toString();
    }
}
