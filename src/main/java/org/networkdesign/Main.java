package org.networkdesign;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Scanner;


/**
 * 这个类是整个项目的入口，集成了所有的功能；
 * 其他的类可以单独执行，也可以通过Main类调用执行
 * 本类主要用于批量测试使用
 */
public class Main {
    private static final String METHOD_NAME = "main";

    private static final Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) throws Exception {

        // 获取发送和接收类
        Class<Send> sendClass = Send.class;
        Class<Capture> captureClass = Capture.class;

        // 获取main方法作为方法
        Method send = sendClass.getDeclaredMethod(METHOD_NAME, String[].class);
        Method capture = captureClass.getDeclaredMethod(METHOD_NAME, String[].class);

        // 创建参数数组
        String[] sendParams = {null,null};
        String[] captureParams = {null,null};

        // 调用main方法
//        send.invoke(null, (Object)sendParams);
//        capture.invoke(null, (Object)captureParams);

        label:
        while (true) {
            System.out.println(
                    "\n>>>请选择要执行的功能:\n" +
                    "---1 协议编辑器\n" +
                    "---2 协议分析器\n" +
                    "---q 退出");
            String option = scanner.next();

            switch (option) {
                case "1":
                    System.out.print(
                            ">>>协议编辑器\n" +
                            "发包次数 >");
                    sendParams[0] = scanner.next();

                    //调用Send.java
                    try {
                        send.invoke(null, (Object) sendParams);
                    } catch (IllegalAccessException | InvocationTargetException | IllegalArgumentException e) {
                        throw new RuntimeException(e);
                    }
                    break;
                case "2":
                    System.out.print(
                            ">>>协议分析器\n" +
                            "抓包次数(-1为无限) >");
                    captureParams[0] = scanner.next();

                    //调用Capture.java
                    try {
                        capture.invoke(null, (Object) captureParams);
                        System.out.println("-[完成]-");
                    } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
                        throw new RuntimeException(e);
                    }
                    break;
                case "q":

                    //退出程序
                    break label;
            }
        }
    }

}
