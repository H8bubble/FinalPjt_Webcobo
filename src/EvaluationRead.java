import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

import javax.crypto.SecretKey;

// 교수자 열람 프로그램
// 전자봉투 복호화 -> 해시 검증 -> 전자서명 검증 -> AES 복호화 -> 평가 내용 출력
public class EvaluationRead {

    public static void main(String[] args) {
        // try-with-resources 로 Scanner 자원을 항상 안전하게 해제
        try (Scanner scanner = new Scanner(System.in)) {
            run(scanner);
        } catch (GeneralSecurityException | IOException e) {
            // 사용자에게는 일반화된 메시지만 노출
            System.out.println();
            System.out.println("열람 처리 중 오류가 발생했습니다: " + e.getClass().getSimpleName());
            System.out.println("(개인키가 올바른지, 파일이 손상되지 않았는지 확인하세요.)");
            System.out.println("========================================");
        }
    }

    private static void run(Scanner scanner) throws GeneralSecurityException, IOException {
        System.out.println("========================================");
        System.out.println(" 전자봉투 기반 익명 동료평가 제출 시스템");
        System.out.println(" [교수자 열람 모드]");
        System.out.println("========================================");
        System.out.println();

        System.out.print("열람할 평가 번호 입력: ");
        String num = scanner.nextLine().trim();
        System.out.print("교수자 개인키 파일명 입력: ");
        String profKeyFile = scanner.nextLine().trim();
        System.out.println();

        // 1. 저장된 파일 모두 불러오기
        byte[] encrypted = FileUtil.readBytes("evaluation_" + num + ".enc");
        byte[] envelope = FileUtil.readBytes("envelope_professor_" + num + ".bin");
        String savedHash = FileUtil.readString("hash_" + num + ".txt");
        byte[] signature = FileUtil.readBytes("signature_" + num + ".bin");
        String meta = FileUtil.readString("submit_meta_" + num + ".txt");

        System.out.println("[1] 저장된 평가 데이터 불러오기 완료");
        System.out.println();

        // 2. 전자봉투 복호화 -> AES 키 복구 (Key Recovery)
        PrivateKey professorPrivKey = MyKeyPair.loadPrivateKey(profKeyFile);
        SecretKey aesKey = EnvelopeUtil.openEnvelope(envelope, professorPrivKey);
        System.out.println("[2] 전자봉투 복호화 완료 (교수자 개인키로 AES 키 복구)");
        System.out.println();

        // 3. 무결성 검증: 저장된 해시와 상수 시간 비교
        boolean hashOk = CryptoUtil.verifyHash(encrypted, savedHash);
        System.out.println("[3] 평가 데이터 해시 검증");
        System.out.println(" - 저장된 해시값: " + savedHash.substring(0, 16) + " ...");
        System.out.println(" - 해시 검증 결과: " + hashOk);
        System.out.println();

        if (!hashOk) {
            System.out.println("경고: 평가 데이터가 제출 이후 변경되었을 가능성이 있습니다.");
            System.out.println("평가 내용을 신뢰할 수 없으므로 열람을 중단합니다.");
            System.out.println("========================================");
            return;
        }

        // 4. 전자서명 검증
        System.out.print("학생 공개키 파일명 입력: ");
        String studentPubKeyFile = scanner.nextLine().trim();
        PublicKey studentPubKey = MyKeyPair.loadPublicKey(studentPubKeyFile);

        // 메타데이터에서 서명 대상 정보 복원 (해시값은 방금 검증한 저장 해시 사용)
        String anonymousId = extractMetaValue(meta, "anonymousSubmitterId");
        String course = extractMetaValue(meta, "course");
        String team = extractMetaValue(meta, "team");
        String target = extractMetaValue(meta, "target");
        String submittedAt = extractMetaValue(meta, "submittedAt");
        String signTarget = anonymousId + "|" + course + "|" + team + "|" + target + "|" + submittedAt + "|" + savedHash;

        boolean signOk = SignatureUtil.verify(signTarget.getBytes(StandardCharsets.UTF_8), signature, studentPubKey);
        System.out.println("[4] 전자서명 검증 (SHA256withRSA)");
        System.out.println(" - 서명 검증 결과: " + signOk);
        System.out.println();

        if (!signOk) {
            System.out.println("경고: 제출자의 전자서명이 유효하지 않습니다.");
            System.out.println("실제 수강생이 제출한 평가인지 확인할 수 없어 반영을 중단합니다.");
            System.out.println("========================================");
            return;
        }

        // 5. AES 키로 평가 데이터 복호화
        byte[] decrypted = CryptoUtil.decryptAES(encrypted, aesKey);
        String evaluationJson = new String(decrypted, StandardCharsets.UTF_8);
        System.out.println("[5] 평가 데이터 복호화 완료");
        System.out.println();

        System.out.println("========================================");
        System.out.println(" 평가 내용");
        System.out.println("========================================");
        System.out.println(evaluationJson);
        System.out.println("========================================");
        System.out.println();
        System.out.println("검증 결과:");
        System.out.println(" - 데이터 무결성: 정상");
        System.out.println(" - 제출자 전자서명: 정상");
        System.out.println(" - 열람 권한: 교수자 인증 완료");
        System.out.println();
        System.out.println("평가 열람이 완료되었습니다.");
        System.out.println("========================================");
    }

    // 메타데이터 파일에서 key= 값 추출
    private static String extractMetaValue(String meta, String key) {
        String[] lines = meta.split("\n");
        for (String line : lines) {
            if (line.startsWith(key + "=")) {
                return line.substring(key.length() + 1).trim();
            }
        }
        return "";
    }
}
