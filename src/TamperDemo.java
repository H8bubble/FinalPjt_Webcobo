import java.io.IOException;

// [데모용] 무결성 검증 시연 도구
// 암호화된 평가 파일의 마지막 바이트 1개를 바꿔(변조해) 해시 검증이
// 실패하는지 보여 주기 위한 보조 프로그램이다. (핵심 시스템 구성요소 아님)
public class TamperDemo {

    public static void main(String[] args) {
        String num = (args.length > 0) ? args[0] : "001";
        String filename = "evaluation_" + num + ".enc";

        try {
            byte[] data = FileUtil.readBytes(filename);
            if (data.length == 0) {
                System.out.println("변조할 데이터가 없습니다: " + filename);
                return;
            }

            // 마지막 바이트의 비트 하나를 뒤집어 내용을 1바이트 변조
            int last = data.length - 1;
            byte before = data[last];
            data[last] = (byte) (data[last] ^ 0x01);
            FileUtil.saveBytes(filename, data);

            System.out.println("========================================");
            System.out.println(" [데모] 평가 데이터 변조 완료");
            System.out.println("========================================");
            System.out.println(" - 대상 파일: " + filename);
            System.out.println(" - 변조 위치: 마지막 바이트 (index " + last + ")");
            System.out.printf(" - 값 변경: 0x%02X -> 0x%02X%n", before & 0xFF, data[last] & 0xFF);
            System.out.println();
            System.out.println("이제 EvaluationRead 를 실행하면 해시 검증이 실패합니다.");
            System.out.println("========================================");
        } catch (IOException e) {
            System.out.println("파일 처리 중 오류: " + e.getClass().getSimpleName());
            System.out.println("먼저 EvaluationSubmit 으로 평가를 제출했는지 확인하세요.");
        }
    }
}
