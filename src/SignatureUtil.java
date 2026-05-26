import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

// 전자서명 생성/검증 클래스 (SHA256withRSA)
public class SignatureUtil {

    // 데이터에 대해 학생 개인키로 전자서명 생성
    public static byte[] sign(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    // 학생 공개키로 전자서명 검증
    public static boolean verify(byte[] data, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }
}
