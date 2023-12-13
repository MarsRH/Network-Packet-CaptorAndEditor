import org.networkdesign.Capture;
import org.networkdesign.Send;
import org.pcap4j.util.ByteArrays;

import java.lang.reflect.Method;

/**
 * 测试用类
 */
public class test {
    private static final String METHOD_NAME = "main";

    public static void main(String[] args) throws Exception {

        //测试使用
//        Logger logger = Logger.getLogger(Main.class.getName());
//        Log.sendLog(logger, "SEND MSG");
//        Log.captureLog(logger, "CAPTURE MSG");

        String awa = "aaaa    ";
        System.out.println(ByteArrays.getInt(awa.getBytes(), 0));

        int qwq = 1952805748;
        System.out.println(new String( ByteArrays.toByteArray(qwq)));

        // 获取发送和接收类
        Class<Send> sendClass = Send.class;
        Class<Capture> captureClass = Capture.class;

        // 获取main方法作为方法
        Method send = sendClass.getDeclaredMethod(METHOD_NAME, String[].class);
        Method capture = captureClass.getDeclaredMethod(METHOD_NAME, String[].class);

        // 创建参数数组
        String[] sendParams = {"param1", "param2"};
        String[] captureParams = {"test1","test2"};

        // 调用main方法
//        send.invoke(null, (Object)sendParams);
//        capture.invoke(null, (Object)captureParams);
    }
}
