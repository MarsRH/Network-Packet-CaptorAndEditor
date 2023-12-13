package org.networkdesign;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.net.SyslogAppender;

/**
 * 自定义收包发包日志输出类
 */
public class Log {

    /**
     * 继承Level
     */
    private static class SendLogLevel extends Level {
        public SendLogLevel(int level, String levelStr, int syslogEquivalent) {
            super(level, levelStr, syslogEquivalent);
        }
    }
    private static class CaptureLogLever extends Level {
        public CaptureLogLever(int level, String leverStr, int syslogEquivalent) {
            super(level, leverStr, syslogEquivalent);
        }
    }

    /**
     * 自定义级别名称，以及级别范围
     */
    private static final Level SendLevel = new SendLogLevel(20050,"SEND", SyslogAppender.LOG_LOCAL0);
    private static final Level CaptureLevel = new CaptureLogLever(30050,"CAPTURE", SyslogAppender.LOG_LOCAL0);

    /**
     * 使用日志打印logger中的log方法
     * 打印发包信息
     *
     * @param logger Logger
     * @param objLogInfo Object
     */
    public static void sendLog(Logger logger, Object objLogInfo){
        logger.log(SendLevel, objLogInfo);
    }

    /**
     * 使用日志打印logger中的log方法
     * 打印抓包信息
     *
     * @param logger Logger
     * @param objLogInfo Object
     */
    public static void captureLog(Logger logger, Object objLogInfo){
        logger.log(CaptureLevel, objLogInfo);
    }

}
