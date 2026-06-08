import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

// 전자서명 생성/검증 클래스 (SHA256withRSA)
public class SignatureUtil {

    private static final String SIGN_ALGORITHM = "SHA256withRSA";

    // 데이터에 대해 학생 개인키로 전자서명 생성
    public static byte[] sign(byte[] data, PrivateKey privateKey)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(SIGN_ALGORITHM);
        signature.initSign(privateKey); // Signature 는 내부적으로 SecureRandom 사용
        signature.update(data);
        return signature.sign();
    }

    // 학생 공개키로 전자서명 검증
    public static boolean verify(byte[] data, byte[] signatureBytes, PublicKey publicKey)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(SIGN_ALGORITHM);
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }
}
