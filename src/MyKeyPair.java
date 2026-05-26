import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

// RSA 공개키/개인키 생성, 저장, 복구 (Key Management)
public class MyKeyPair {

    // RSA 키쌍 생성 후 두 개의 파일에 저장
    public static void generateAndSave(String publicKeyFile, String privateKeyFile) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();

        // 공개키와 개인키를 byte[]로 변환하여 파일에 저장
        FileUtil.saveBytes(publicKeyFile, pair.getPublic().getEncoded());
        FileUtil.saveBytes(privateKeyFile, pair.getPrivate().getEncoded());

        System.out.println("RSA 키쌍 생성 완료");
        System.out.println(" - 공개키 파일: " + publicKeyFile);
        System.out.println(" - 개인키 파일: " + privateKeyFile);
    }

    // 파일에서 공개키를 읽어 PublicKey 객체로 복구
    public static PublicKey loadPublicKey(String filename) throws Exception {
        byte[] keyBytes = FileUtil.readBytes(filename);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePublic(spec);
    }

    // 파일에서 개인키를 읽어 PrivateKey 객체로 복구
    public static PrivateKey loadPrivateKey(String filename) throws Exception {
        byte[] keyBytes = FileUtil.readBytes(filename);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePrivate(spec);
    }

    // 학생용, 교수자용 키쌍을 한 번에 생성하는 메인
    public static void main(String[] args) throws Exception {
        System.out.println("========================================");
        System.out.println(" RSA 키쌍 생성 프로그램");
        System.out.println("========================================");

        // 학생용 키쌍
        generateAndSave("student_public.key", "student_private.key");
        System.out.println();

        // 교수자용 키쌍
        generateAndSave("professor_public.key", "professor_private.key");
        System.out.println();

        System.out.println("모든 키쌍 생성이 완료되었습니다.");
        System.out.println("========================================");
    }
}
