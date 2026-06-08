import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Set;

// RSA 공개키/개인키 생성, 저장, 복구 (Key Management)
public class MyKeyPair {

    private static final int RSA_KEY_SIZE = 2048;

    // RSA 키쌍 생성 후 두 개의 파일에 저장
    public static void generateAndSave(String publicKeyFile, String privateKeyFile)
            throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(RSA_KEY_SIZE); // 내부적으로 SecureRandom 사용
        KeyPair pair = generator.generateKeyPair();

        // 공개키(X.509)와 개인키(PKCS#8)를 byte[]로 변환하여 파일에 저장
        FileUtil.saveBytes(publicKeyFile, pair.getPublic().getEncoded());
        FileUtil.saveBytes(privateKeyFile, pair.getPrivate().getEncoded());

        // 개인키 파일은 소유자 전용 권한으로 제한 (지원하는 OS에서만)
        restrictToOwnerOnly(privateKeyFile);

        System.out.println("RSA 키쌍 생성 완료");
        System.out.println(" - 공개키 파일: " + publicKeyFile);
        System.out.println(" - 개인키 파일: " + privateKeyFile);
    }

    // 개인키 파일 권한을 rw------- (600) 으로 설정. POSIX 미지원 환경이면 조용히 건너뜀.
    private static void restrictToOwnerOnly(String privateKeyFile) {
        try {
            Path path = Paths.get(privateKeyFile);
            if (path.getFileSystem().supportedFileAttributeViews().contains("posix")) {
                Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
                Files.setPosixFilePermissions(path, perms);
            }
        } catch (IOException | UnsupportedOperationException e) {
            System.out.println(" - (안내) 개인키 파일 권한 설정을 건너뜀: " + e.getMessage());
        }
    }

    // 파일에서 공개키를 읽어 PublicKey 객체로 복구
    public static PublicKey loadPublicKey(String filename)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = FileUtil.readBytes(filename);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePublic(spec);
    }

    // 파일에서 개인키를 읽어 PrivateKey 객체로 복구
    public static PrivateKey loadPrivateKey(String filename)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = FileUtil.readBytes(filename);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePrivate(spec);
    }

    // 학생용, 교수자용 키쌍을 한 번에 생성하는 메인
    public static void main(String[] args) {
        System.out.println("========================================");
        System.out.println(" RSA 키쌍 생성 프로그램");
        System.out.println("========================================");

        try {
            // 학생용 키쌍
            generateAndSave("student_public.key", "student_private.key");
            System.out.println();

            // 교수자용 키쌍
            generateAndSave("professor_public.key", "professor_private.key");
            System.out.println();

            System.out.println("모든 키쌍 생성이 완료되었습니다.");
        } catch (GeneralSecurityException | IOException e) {
            // 사용자에게는 일반화된 메시지만 노출 (상세 스택은 출력하지 않음)
            System.out.println("키 생성 중 오류가 발생했습니다: " + e.getClass().getSimpleName());
        }
        System.out.println("========================================");
    }
}
