import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

// 파일 읽기/쓰기 유틸리티 클래스
public class FileUtil {

    // byte[] 데이터를 파일에 저장
    public static void saveBytes(String filename, byte[] data) throws IOException {
        FileOutputStream fos = new FileOutputStream(filename);
        fos.write(data);
        fos.close();
    }

    // 파일에서 byte[] 데이터를 읽어 옴
    public static byte[] readBytes(String filename) throws IOException {
        File file = new File(filename);
        FileInputStream fis = new FileInputStream(file);
        byte[] data = new byte[(int) file.length()];
        fis.read(data);
        fis.close();
        return data;
    }

    // 문자열을 파일에 저장
    public static void saveString(String filename, String content) throws IOException {
        FileWriter fw = new FileWriter(filename);
        fw.write(content);
        fw.close();
    }

    // 파일에서 문자열을 읽어 옴 (줄바꿈 유지)
    public static String readString(String filename) throws IOException {
        BufferedReader br = new BufferedReader(new FileReader(filename));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) {
            sb.append(line).append("\n");
        }
        br.close();
        return sb.toString().trim();
    }
}
