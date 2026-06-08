import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

// 전자봉투 생성/복호화 클래스
// 평가 데이터 암호화에 사용한 AES 키를 RSA로 한 번 더 감싸는 역할
public class EnvelopeUtil {

    // 운영 모드/패딩을 명시적으로 지정 (Provider 기본값에 의존하지 않음)
    private static final String RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding";

    // 전자봉투 생성: AES 키를 RSA 공개키로 암호화
    public static byte[] createEnvelope(SecretKey aesKey, PublicKey publicKey)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
                   IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(aesKey.getEncoded());
    }

    // 전자봉투 복호화: RSA 개인키로 복호화하여 AES 키 복구 (Key Recovery)
    public static SecretKey openEnvelope(byte[] envelope, PrivateKey privateKey)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
                   IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] aesKeyBytes = cipher.doFinal(envelope);
        return CryptoUtil.bytesToAESKey(aesKeyBytes);
    }
}
