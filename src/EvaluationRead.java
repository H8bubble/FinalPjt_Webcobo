import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

import javax.crypto.SecretKey;

// 교수자 열람 프로그램
// 전자봉투 복호화 -> 해시 검증 -> 전자서명 검증 -> AES 복호화 -> 평가 내용 출력
public class EvaluationRead {

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        System.out.println("========================================");
        System.out.println(" 전자봉투 기반 익명 동료평가 제출 시스템");
        System.out.println(" [교수자 열람 모드]");
        System.out.println("========================================");
        System.out.println();

        System.out.print("열람할 평가 번호 입력: ");
        String num = scanner.nextLine();
        System.out.print("교수자 개인키 파일명 입력: ");
        String profKeyFile = scanner.nextLine();
        System.out.println();

        // 1. 저장된 파일 모두 불러오기
        byte[] encrypted = FileUtil.readBytes("evaluation_" + num + ".enc");
        byte[] envelope = FileUtil.readBytes("envelope_professor_" + num + ".bin");
        String savedHash = FileUtil.readString("hash_" + num + ".txt");
        byte[] signature = FileUtil.readBytes("signature_" + num + ".bin");
        String meta = FileUtil.readString("submit_meta_" + num + ".txt");

        System.out.println("[1] 저장된 평가 데이터 불러오기 완료");
        System.out.println(" - evaluation_" + num + ".enc");
        System.out.println(" - envelope_professor_" + num + ".bin");
        System.out.println(" - hash_" + num + ".txt");
        System.out.println(" - signature_" + num + ".bin");
        System.out.println(" - submit_meta_" + num + ".txt");
        System.out.println();

        // 2. 전자봉투 복호화 -> AES 키 복구
        PrivateKey professorPrivKey = MyKeyPair.loadPrivateKey(profKeyFile);
        SecretKey aesKey = EnvelopeUtil.openEnvelope(envelope, professorPrivKey);
        System.out.println("[2] 전자봉투 복호화 중...");
        System.out.println(" - 교수자 개인키로 AES 키 복호화 완료");
        System.out.println();

        // 3. 무결성 검증: 저장된 해시 vs 새로 계산한 해시
        byte[] currentHash = CryptoUtil.sha256(encrypted);
        String currentHashHex = CryptoUtil.bytesToHex(currentHash);
        boolean hashOk = savedHash.equalsIgnoreCase(currentHashHex);

        System.out.println("[3] 평가 데이터 해시 검증 중...");
        System.out.println(" - 저장된 해시값: " + savedHash.substring(0, 16) + " ...");
        System.out.println(" - 계산된 해시값: " + currentHashHex.substring(0, 16) + " ...");
        System.out.println(" - 해시 검증 결과: " + hashOk);
        System.out.println();

        if (!hashOk) {
            System.out.println("경고: 평가 데이터가 제출 이후 변경되었을 가능성이 있습니다.");
            System.out.println("평가 내용을 신뢰할 수 없으므로 복호화 및 열람을 중단합니다.");
            System.out.println("========================================");
            scanner.close();
            return;
        }

        // 4. 전자서명 검증
        System.out.print("학생 공개키 파일명 입력: ");
        String studentPubKeyFile = scanner.nextLine();
        PublicKey studentPubKey = MyKeyPair.loadPublicKey(studentPubKeyFile);

        // 메타데이터에서 서명 대상 정보 복원
        String anonymousId = extractMetaValue(meta, "anonymousSubmitterId");
        String course = extractMetaValue(meta, "course");
        String team = extractMetaValue(meta, "team");
        String submittedAt = extractMetaValue(meta, "submittedAt");
        String signTarget = anonymousId + "|" + course + "|" + team + "|" + submittedAt + "|" + currentHashHex;

        boolean signOk = SignatureUtil.verify(signTarget.getBytes("UTF-8"), signature, studentPubKey);

        System.out.println("[4] 전자서명 검증 중...");
        System.out.println(" - 입력된 서명 정보: " + signature.length + " bytes");
        System.out.println(" - 서명 알고리즘: SHA256withRSA");
        System.out.println(" - 서명 검증 결과: " + signOk);
        System.out.println();

        if (!signOk) {
            System.out.println("경고: 제출자의 전자서명이 유효하지 않습니다.");
            System.out.println("실제 수강생이 제출한 평가인지 확인할 수 없습니다.");
            System.out.println("평가 반영을 중단합니다.");
            System.out.println("========================================");
            scanner.close();
            return;
        }

        // 5. AES 키로 평가 데이터 복호화
        byte[] decrypted = CryptoUtil.decryptAES(encrypted, aesKey);
        String evaluationJson = new String(decrypted, "UTF-8");

        System.out.println("[5] 평가 데이터 복호화 중...");
        System.out.println(" - AES 복호화 완료");
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

        scanner.close();
    }

    // 메타데이터 파일에서 key= 값 추출
    private static String extractMetaValue(String meta, String key) {
        String[] lines = meta.split("\n");
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            if (line.startsWith(key + "=")) {
                return line.substring(key.length() + 1).trim();
            }
        }
        return "";
    }
}
