import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

// AES 암호화/복호화 + SHA-256 해시 + 보조 유틸
public class CryptoUtil {

    // AES/CBC 운영 모드를 명시적으로 사용 (기본값 ECB 사용 금지)
    private static final String AES_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int AES_KEY_SIZE = 128;
    private static final int IV_SIZE = 16; // AES 블록 크기(=IV 길이)

    // AES 128bit 대칭키 생성
    public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(AES_KEY_SIZE); // KeyGenerator 는 내부적으로 SecureRandom 사용
        return generator.generateKey();
    }

    // AES로 데이터 암호화: 매번 새 IV 를 만들고 [IV(16) || 암호문] 형태로 반환
    public static byte[] encryptAES(byte[] data, SecretKey key)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
                   InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv); // 매 암호화마다 무작위 IV 생성

        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] cipherText = cipher.doFinal(data);

        // IV 를 암호문 앞에 붙여서 함께 저장한다 (복호화 시 분리)
        byte[] result = new byte[IV_SIZE + cipherText.length];
        System.arraycopy(iv, 0, result, 0, IV_SIZE);
        System.arraycopy(cipherText, 0, result, IV_SIZE, cipherText.length);
        return result;
    }

    // AES로 데이터 복호화: 앞 16바이트를 IV로 분리한 뒤 복호화
    public static byte[] decryptAES(byte[] encryptedData, SecretKey key)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
                   InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        if (encryptedData.length < IV_SIZE) {
            throw new IllegalArgumentException("암호문 길이가 IV 길이보다 짧습니다.");
        }
        byte[] iv = new byte[IV_SIZE];
        byte[] cipherText = new byte[encryptedData.length - IV_SIZE];
        System.arraycopy(encryptedData, 0, iv, 0, IV_SIZE);
        System.arraycopy(encryptedData, IV_SIZE, cipherText, 0, cipherText.length);

        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(cipherText);
    }

    // byte[] -> SecretKey 객체로 복구 (전자봉투에서 꺼낸 AES 키 복구용)
    public static SecretKey bytesToAESKey(byte[] keyBytes) {
        return new SecretKeySpec(keyBytes, "AES");
    }

    // SHA-256 해시 계산
    public static byte[] sha256(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data);
    }

    // byte[] -> 16진수 문자열 (해시값 표시/저장용)
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    // 데이터를 다시 해싱하여 저장된 해시(16진수)와 상수 시간 비교로 무결성 검증
    public static boolean verifyHash(byte[] data, String expectedHex) throws NoSuchAlgorithmException {
        byte[] expected = hexToBytes(expectedHex);
        byte[] actual = sha256(data);
        // MessageDigest.isEqual 은 타이밍 공격을 방지하는 상수 시간 비교를 수행한다
        return MessageDigest.isEqual(expected, actual);
    }

    // 16진수 문자열 -> byte[]
    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return out;
    }
}
