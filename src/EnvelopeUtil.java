import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

// 전자봉투 생성/복호화 클래스
// 평가 데이터 암호화에 사용한 AES 키를 RSA로 한 번 더 감싸는 역할
public class EnvelopeUtil {

    // 전자봉투 생성: AES 키를 RSA 공개키로 암호화
    public static byte[] createEnvelope(SecretKey aesKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(aesKey.getEncoded());
    }

    // 전자봉투 복호화: RSA 개인키로 복호화하여 AES 키 복구
    public static SecretKey openEnvelope(byte[] envelope, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] aesKeyBytes = cipher.doFinal(envelope);
        return CryptoUtil.bytesToAESKey(aesKeyBytes);
    }
}
