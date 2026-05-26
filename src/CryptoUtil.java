import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

// AES 암호화/복호화 + SHA-256 해시 + 보조 유틸
public class CryptoUtil {

    // AES 128bit 대칭키 생성
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        return generator.generateKey();
    }

    // AES로 데이터 암호화
    public static byte[] encryptAES(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    // AES로 데이터 복호화
    public static byte[] decryptAES(byte[] encryptedData, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encryptedData);
    }

    // byte[] -> SecretKey 객체로 복구 (AES 키 복구용)
    public static SecretKey bytesToAESKey(byte[] keyBytes) {
        return new SecretKeySpec(keyBytes, "AES");
    }

    // SHA-256 해시 계산
    public static byte[] sha256(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data);
    }

    // byte[] -> 16진수 문자열 (해시값 표시용)
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
