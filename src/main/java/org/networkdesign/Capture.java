package org.networkdesign;

import org.apache.log4j.Logger;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.util.NifSelector;

import java.io.IOException;
import java.util.Arrays;
import java.util.Scanner;

/**
 * 抓包工具类
 * 可选参数arg[0]:抓取次数
 */
public class Capture {

    private static final String COUNT_KEY = Capture.class.getName() + ".count";
    private static int COUNT = Integer.getInteger(COUNT_KEY, -1); //抓取次数

    private static final String READ_TIMEOUT_KEY = Capture.class.getName() + ".readTimeout";
    private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

    private static final String SNAPLEN_KEY = Capture.class.getName() + ".snaplen";
    private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

    private static final Logger LOGGER = Logger.getLogger(Capture.class.getName());

    public static void main(String[] args) throws PcapNativeException, NotOpenException {

        //处理Main传入参数
        if (args.length != 0 && !args[0].equals("0")) {
            COUNT = Integer.parseInt(args[0]);
            System.out.println("[PARAMS]" + args[0] + args[1]);
        }
        Scanner scanner = new Scanner(System.in);

        //获取网卡信息
        PcapNetworkInterface nif;
        try {
            nif = new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }
        if (nif == null) {
            return;
        }
        System.out.println(nif.getName() + "(" + nif.getDescription() + ")");

        //获取Handle
        final PcapHandle handle = nif.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);

        //获取用户输入过滤条件
        System.out.print(">>>请输入过滤条件:");
        String filter = scanner.nextLine();


        //设置过滤器
        if (!filter.isEmpty()) {
            try {
                handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);
                System.out.println("当前过滤规则>>>[" + filter + "]");
            } catch (PcapNativeException | NotOpenException e) {
                throw new RuntimeException(e);
            }
        }

        //设置监听器
        PacketListener listener =
                pcapPacket -> {
                    EthernetPacket ethernetPacket = pcapPacket.get(EthernetPacket.class);
                    //获取以太网帧头部
                    EthernetPacket.EthernetHeader ethernetHeader = ethernetPacket.getHeader();

                    String msg =
                            "---<以太网MAC协议>----------------------------------------\n" +
                            String.format("%-20s%-20s%-14s\n", "目的MAC地址", "源MAC地址", "类型") +
                            String.format("|%-20s|%-20s|%-15s\n", ethernetHeader.getDstAddr(), ethernetHeader.getSrcAddr(), ethernetHeader.getType());

                    //解析下一层协议字段
                    EtherType type = ethernetHeader.getType();
                    if (type == EtherType.IPV4) {
                        parseIpV4Packet(pcapPacket.get(IpV4Packet.class), msg);    //IPV4协议
                    } else if (type == EtherType.IPV6) {
                        parseIpV6Packet(pcapPacket.get(IpV6Packet.class), msg);    //IPV6协议
                    } else if (type == EtherType.ARP) {
                        parseArpPacket(pcapPacket.get(ArpPacket.class), msg);      //ARP协议
                    } else if (type.toString().contains("0x1145")) {
                        parseShitPacket(ethernetPacket.getPayload().getRawData(), msg);  //Shit协议
                    } else {
                        Log.captureLog(LOGGER, msg);    //输出至日志
                    }
                };


        //尝试开始循环
        try {
            handle.loop(COUNT,listener);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        //回收资源
        handle.close();
    }

    //解析各协议的方法

    /**
     * 解析IP报文
     * @param packet IpV4Packet
     * @param msg String
     */
    private static void parseIpV4Packet(IpV4Packet packet, String msg) {
        //获取头部
        IpV4Packet.IpV4Header header = packet.getHeader();

        //将各字段添加至输出字符串中
        msg +=
                "\n---<IP协议>---" +
                "\n版本:\t" + header.getVersion() +
                "\t首部长度:\t" + header.getIhl() +
                "\n服务类型:\t" + header.getTos() +
                "\n总长度:\t" + header.getTotalLength() +
                "\t标识:\t" + Integer.toHexString(header.getIdentification()) +
                "\t片偏移:\t" + header.getFragmentOffset() +
                "\t生存时间:\t" + header.getTtl() +
                "\n高层协议类型:\t" + header.getProtocol() +
                "\t首部校验和:\t" + Integer.toHexString(header.getHeaderChecksum()) +
                "\n源IP地址:\t" + header.getSrcAddr() +
                "\t目的IP地址:\t" + header.getDstAddr() +
                "\n可选字段:\t" + header.getOptions() +
                "\t填充:\t" + Arrays.toString(header.getPadding())+"\n";

        //解析上层协议
        if (header.getProtocol() == IpNumber.TCP) {
            parseTcpPacket(packet.get(TcpPacket.class), msg);
        } else if (header.getProtocol() == IpNumber.UDP) {
            parseUdpPacket(packet.get(UdpPacket.class), msg);
        } else if (header.getProtocol() == IpNumber.ICMPV4) {
            parseIcmpPacket(packet.get(IcmpV4CommonPacket.class), msg);
        } else {
            Log.captureLog(LOGGER, msg);    //输出至日志
        }
    }


    private static void parseIpV6Packet(IpV6Packet packet, String msg) {
        //获取头部
        IpV6Packet.IpV6Header header = packet.getHeader();

        //将各字段添加至输出字符串中
        msg +=
                "\n---<IP协议>---" +
                        "\n版本:\t" + header.getVersion() +
                        "\t高层协议类型:\t" + header.getProtocol() +
                        "\n源IP地址:\t" + header.getSrcAddr() +
                        "\n目的IP地址:\t" + header.getDstAddr()+"\n";

        //解析上层协议
        if (header.getProtocol() == IpNumber.TCP) {
            parseTcpPacket(packet.get(TcpPacket.class), msg);
        } else if (header.getProtocol() == IpNumber.UDP) {
            parseUdpPacket(packet.get(UdpPacket.class), msg);
        } else if (header.getProtocol() == IpNumber.ICMPV4) {
            parseIcmpPacket(packet.get(IcmpV4CommonPacket.class), msg);
        } else {
            Log.captureLog(LOGGER, msg);    //输出至日志
        }
    }

    /**
     * 解析Arp报文
     * @param packet ArpPacket
     * @param msg String
     */
    private static void parseArpPacket(ArpPacket packet, String msg) {
        //获取头部
        ArpPacket.ArpHeader header = packet.getHeader();

        //将各字段添加至输出字符串中
        msg +=
                "\n---<ARP协议>---" +
                "\n硬件类型:\t" + header.getHardwareType() +
                "\t协议类型:\t" + header.getProtocolType() +
                "\n硬件地址长度:\t" + header.getHardwareAddrLength() +
                "\t协议地址长度:\t" + header.getProtocolAddrLength() +
                "\n操作码:\t" + header.getOperation() +
                "\n发送端硬件地址:\t" + header.getSrcHardwareAddr() +
                "\n发送端逻辑地址:\t" + header.getSrcProtocolAddr() +
                "\n目的端硬件地址:\t" + header.getDstHardwareAddr() +
                "\n目的端逻辑地址:\t" + header.getDstProtocolAddr();

        Log.captureLog(LOGGER, msg);    //输出至日志
    }

    /**
     * 解析TCP报文
     * @param packet TcpPacket
     * @param msg String
     */
    private static void parseTcpPacket(TcpPacket packet, String msg) {
        //获取头部
        TcpPacket.TcpHeader header = packet.getHeader();

        //将各字段添加至输出字符串中
        msg +=
                "\n---<TCP协议>---" +
                "\n源端口:\t" + header.getSrcPort() +
                "\t目的端口:\t" + header.getDstPort() +
                "\n序列号:\t" + header.getSequenceNumber() +
                "\n确认:\t" + header.getAcknowledgmentNumber() +
                "\n首部长度:\t" + header.length() +
                "\t保留:\t" + header.getReserved() +
                "\nURG:\t" + header.getUrg() +
                "\tACK:\t" + header.getAck() +
                "\tPSH:\t" + header.getPsh() +
                "\tRST:\t" + header.getRst() +
                "\tSYN:\t" + header.getSyn() +
                "\tFIN:\t" + header.getFin() +
                "\n窗口大小:\t" + header.getWindow() +
                "\t校验和:\t" + Integer.toHexString(header.getChecksum()) +
                "\t紧急指针:\t" + header.getUrgentPointer() +
                "\n选项和填充:\t" + header.getOptions() + Arrays.toString(header.getPadding()) +
                "\n数据部分:\t" + packet.getPayload();

        Log.captureLog(LOGGER, msg);    //输出至日志
    }

    /**
     * 解析UDP报文
     * @param packet UdpPacket
     * @param msg String
     */
    private static void parseUdpPacket(UdpPacket packet, String msg) {
        //获取头部
        UdpPacket.UdpHeader header = packet.getHeader();

        //将各字段添加至输出字符串中
        msg +=
                "\n---<UDP协议>---" +
                "\n源端口地址:\t" + header.getSrcPort() +
                "\n目的端口地址:\t" + header.getDstPort() +
                "\nUDP总长度:\t" + header.getLength() +
                "\n检验和:\t" + header.getChecksum() +
                "\n数据:\t" + packet.getPayload();

        Log.captureLog(LOGGER, msg);    //输出至日志
    }

    private static void parseIcmpPacket(IcmpV4CommonPacket packet, String msg){
        //获取头部
        IcmpV4CommonPacket.IcmpV4CommonHeader header = packet.getHeader();

        //将各字段添加至输出字符串中
        msg +=
                "\n---<ICMP协议>---" +
                "\n类型:\t" + header.getType() +
                "\n代码:\t" + header.getCode() +
                "\n首部校验和:\t" + header.getChecksum();

        Log.captureLog(LOGGER, msg);
    }

    /**
     * 解析自定义报文
     * @param rawData ShitPacket's rawData
     * @param msg String
     */
    private static void parseShitPacket(byte[] rawData, String msg) {
        ShitPacket shitPacket;

        //根据原始数据构建自定义包
        try {
            shitPacket = ShitPacket.newPacket(rawData, 0, rawData.length);
        } catch (IllegalRawDataException e) {
            throw new RuntimeException(e);
        }

        //获取头部
        ShitPacket.ShitHeader header = shitPacket.getHeader();

        //解析字段
        msg +=
                "\n---<SHIT协议(自定义协议)>---" +
                "\n协议类型:\t" + header.getShit() +
                "\n质量:\t" + header.getQuality() +
                "\n首部长度:\t" + header.getLength() +
                "\n目标状态:\t" + header.getDstStatus() +
                "\n源状态:\t" + header.getSrcStatus() +
                "\n详细信息:\t" + header.getDetails();

        Log.captureLog(LOGGER, msg);    //输出至日志
    }
}
