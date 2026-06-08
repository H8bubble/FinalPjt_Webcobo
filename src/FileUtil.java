import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

// 파일 읽기/쓰기 유틸리티 클래스
public class FileUtil {

    // byte[] 데이터를 파일에 저장 (자원 자동 해제는 Files API가 처리)
    public static void saveBytes(String filename, byte[] data) throws IOException {
        Files.write(Paths.get(filename), data);
    }

    // 파일에서 byte[] 데이터를 모두 읽어 옴 (부분 읽기 방지)
    public static byte[] readBytes(String filename) throws IOException {
        return Files.readAllBytes(Paths.get(filename));
    }

    // 문자열을 파일에 저장 (UTF-8)
    public static void saveString(String filename, String content) throws IOException {
        Files.write(Paths.get(filename), content.getBytes(StandardCharsets.UTF_8));
    }

    // 파일에서 문자열을 읽어 옴 (UTF-8, 앞뒤 공백/줄바꿈 정리)
    public static String readString(String filename) throws IOException {
        byte[] data = Files.readAllBytes(Paths.get(filename));
        return new String(data, StandardCharsets.UTF_8).trim();
    }

    // 파일 존재 여부 확인
    public static boolean exists(String filename) {
        Path path = Paths.get(filename);
        return Files.exists(path);
    }
}
