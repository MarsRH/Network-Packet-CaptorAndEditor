package org.networkdesign;

import org.apache.log4j.Logger;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Scanner;

/**
 * 发包工具类
 * 可选参数arg[0] 抓包次数
 */
public class Send {

    private static final String COUNT_KEY = Send.class.getName() + ".count";
    private static int COUNT = Integer.getInteger(COUNT_KEY, 1);

    private static final String READ_TIMEOUT_KEY = Send.class.getName() + ".readTimeout";
    private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

    private static final String SNAPLEN_KEY = Send.class.getName() + ".snaplen";
    private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

    private static MacAddress SRC_MAC_ADDR = MacAddress.getByName("f8:5e:a0:19:ea:06");   //源mac地址
    private static MacAddress DST_MAC_ADDR = MacAddress.ETHER_BROADCAST_ADDRESS;   //目的mac地址

    private static final Logger LOGGER = Logger.getLogger(Send.class.getName());
    private static final Scanner scanner = new Scanner(System.in);
    private static IpNumber protocol = IpNumber.getInstance((byte)255);
    private static final String SELECT_PROTOCOL =
            ">>>协议类型: \n" + "0、Mac\n" + "1、IP\n" + "2、ARP\n" + "3、TCP\n" + "4、UDP\n" + "5、SHIT(自定义协议)\n" + "请选择 >";

    public static void main(String[] args) throws PcapNativeException, NotOpenException {

        //处理Main传入参数
        if (args.length != 0 && !args[0].equals("0")) {
            COUNT = Integer.parseInt(args[0]);
            System.out.println("[PARAMS]" + args[0] + args[1]);
        }
        Packet.Builder builder = null;
        EtherType type;

        //获取网卡
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
        PcapHandle sendHandle = nif.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);

        //获取以太网MAC帧字段值输入
        System.out.println(">>>构建MAC帧");
        System.out.print("目的MAC地址(默认FF:FF:FF:FF:FF:FF) >");
        String addr = scanner.nextLine();
        if (!addr.isEmpty()) {
            DST_MAC_ADDR = MacAddress.getByName(addr);
        }
        System.out.print("源MAC地址(默认f8:5e:a0:19:ea:06) >");
        addr = scanner.nextLine();
        if (!addr.isEmpty()) {
            SRC_MAC_ADDR = MacAddress.getByName(addr);
        }

        //用户选择发送的协议类型,获取用户输入
        System.out.print(SELECT_PROTOCOL);
        switch (scanner.nextInt()){
            case 0:
                type = EtherType.getInstance((short) 0xFFFF);
                break;
            case 1:
                type = EtherType.IPV4;
                builder = ipV4PacketBuilder();
                break;
            case 2:
                type = EtherType.ARP;
                builder = arpPacketBuilder();
                break;
            case 3:
                type = EtherType.IPV4;
                protocol = IpNumber.TCP;
                builder = ipV4PacketBuilder();
                break;
            case 4:
                type = EtherType.IPV4;
                protocol = IpNumber.UDP;
                builder = ipV4PacketBuilder();
                break;
            case 5:
                type = new EtherType((short)0x1145, "SHIT");
                builder = shitPacketBuilder();
                break;
            default:
                Log.sendLog(LOGGER, "Send Error: No such type");
                return;
        }

        try {
            //构建以太网MAC帧
            EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
            etherBuilder
                    .dstAddr(DST_MAC_ADDR)
                    .srcAddr(SRC_MAC_ADDR)
                    .type(type)
                    .paddingAtBuild(true);
            if (builder!= null) {
                etherBuilder.payloadBuilder(builder);
            }

            //发送数据包
            for (int i = 0; i < COUNT; i++) {
                Packet p = etherBuilder.build();
                Log.sendLog(LOGGER, p);
                sendHandle.sendPacket(p);
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    break;
                }
            }
            Log.sendLog(LOGGER, ">>>运行完成");
        } finally {
            //回收资源
            if (sendHandle.isOpen()) {
                sendHandle.close();
            }

        }
    }

    /**
     * 获取用户输入，构建IP报文
     * @return IpV4Packet.Builder
     */
    private static IpV4Packet.Builder ipV4PacketBuilder(){
        IpV4Packet.Builder builder = new IpV4Packet.Builder();

        try {

            //获取用户输入
            System.out.println(">>>构建IP报文");
            System.out.print("区分服务(服务类型) >");
            int tos = scanner.nextInt();
            System.out.print("生存时间 >");
            int ttl = scanner.nextInt();
            System.out.println("高层协议类型 >"+protocol);
            System.out.print("源IP地址 >");
            String strSrcIpAddress = scanner.next();
            System.out.print("目的IP地址 >");
            String strDstIpAddress = scanner.next();

            //尝试构建头部
            builder
                    .version(IpVersion.IPV4)                                            //版本
                    .tos((IpV4Packet.IpV4Tos) () -> (byte) tos)                         //区分服务
                    .ttl((byte) ttl)                                                    //生存时间
                    .protocol(protocol)                                                 //协议
                    .srcAddr((Inet4Address) Inet4Address.getByName(strSrcIpAddress))    //源地址
                    .dstAddr((Inet4Address) Inet4Address.getByName(strDstIpAddress))    //目的地址
                    .paddingAtBuild(true)
                    .correctLengthAtBuild(true)
                    .correctChecksumAtBuild(true);

            //尝试构建上层报文
            if (protocol == IpNumber.TCP) {
                builder.payloadBuilder(tcpPacketBuilder(strDstIpAddress, strSrcIpAddress));
            } else if (protocol == IpNumber.UDP) {
                builder.payloadBuilder(udpPacketBuilder(strDstIpAddress, strSrcIpAddress));
            } else {
                scanner.nextLine();
                System.out.println(">>>数据");
                byte[] payload =  scanner.nextLine().getBytes();
                if (payload.length != 0) {
                    builder.payloadBuilder(new UnknownPacket.Builder().rawData(payload));
                }
            }

        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }

        return builder;
    }

    /**
     * 获取用户输入，构建ARP报文
     * @return ArpPacket.Builder
     */
    private static ArpPacket.Builder arpPacketBuilder() {
        ArpPacket.Builder builder = new ArpPacket.Builder();

        try {

            //获取用户输入
            System.out.println(">>>构建ARP报文");
            System.out.print("硬件类型 >");
            short hardWareType = scanner.nextShort();
            System.out.println(ArpHardwareType.getInstance(hardWareType));
            System.out.print("协议类型(0x____) >");
            short protocolType = Short.parseShort(scanner.next().substring(2), 16);
//        short protocolType = Short.parseShort(scanner.next());
            System.out.println(EtherType.getInstance(protocolType));
            System.out.print("硬件地址长度 >");
            int hardwareAddrLength = scanner.nextInt();
            System.out.print("协议地址长度 >");
            int protocolAddrLength = scanner.nextInt();
            System.out.print("操作码 >");
            short operation = scanner.nextShort();
            System.out.print("发送端硬件地址 >");
            String srcHardwareAddr = scanner.next();
            System.out.print("发送端逻辑地址 >");
            String srcProtocolAddr = scanner.next();
            System.out.print("目的端硬件地址 >");
            String dstHardwareAddr = scanner.next();
            System.out.print("目的端逻辑地址 >");
            String dstProtocolAddr = scanner.next();

            builder
                    .hardwareType(ArpHardwareType.getInstance(hardWareType))
                    .protocolType(EtherType.getInstance(protocolType))
                    .hardwareAddrLength((byte) hardwareAddrLength)
                    .protocolAddrLength((byte) protocolAddrLength)
                    .operation(ArpOperation.getInstance(operation))
                    .srcHardwareAddr(MacAddress.getByName(srcHardwareAddr))
                    .srcProtocolAddr(InetAddress.getByName(srcProtocolAddr))
                    .dstHardwareAddr(MacAddress.getByName(dstHardwareAddr))
                    .dstProtocolAddr(InetAddress.getByName(dstProtocolAddr));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return builder;
    }

    /**
     * 获取用户输入，构建TCP报文
     * @return TcoPacket.Builder
     */
    private static TcpPacket.Builder tcpPacketBuilder(String strDstAddr, String strSrcAddr) {
        TcpPacket.Builder builder = new TcpPacket.Builder();

        try {

            //获取用户输入
            System.out.println(">>>构建TCP报文");
            System.out.print("源端口 >");
            short srcPort = scanner.nextShort();
            System.out.print("目的端口 >");
            short dstPort = scanner.nextShort();
            System.out.print("序列号 >");
            scanner.nextLine();//吸取一个回车符号
            String tmp = scanner.nextLine();
            int seq = tmp.isEmpty()? 100: Integer.parseInt(tmp);
            System.out.print("确认号 >");
            tmp = scanner.nextLine();
            int ack = tmp.isEmpty()? 100: Integer.parseInt(tmp);
//        System.out.print("首部长度 >");
            System.out.print("URG >");
            boolean URG = scanner.next().equals("1");
            System.out.print("ACK >");
            boolean ACK = scanner.next().equals("1");
            System.out.print("PSH >");
            boolean PSH = scanner.next().equals("1");
            System.out.print("RST >");
            boolean RST = scanner.next().equals("1");
            System.out.print("SYN >");
            boolean SYN = scanner.next().equals("1");
            System.out.print("FIN >");
            boolean FIN = scanner.next().equals("1");
            System.out.print("窗口大小 >");
            short window = scanner.nextShort();
//        System.out.print("校验和 >");
            short urgentPointer = 0;
            if (URG) {
                System.out.print("紧急指针 >");
                urgentPointer = scanner.nextShort();
            }
            scanner.nextLine(); //吸取回车
            System.out.println(">>>数据");
            byte[] payload =  scanner.nextLine().getBytes();
            if (payload.length != 0) {
                builder.payloadBuilder(new UnknownPacket.Builder().rawData(payload));
            }

            builder
                    .dstAddr(InetAddress.getByName(strDstAddr))
                    .srcAddr(InetAddress.getByName(strSrcAddr))
                    .srcPort(TcpPort.getInstance(srcPort))
                    .dstPort(TcpPort.getInstance(dstPort))
                    .sequenceNumber(seq)
                    .acknowledgmentNumber(ack)
                    .urg(URG)
                    .ack(ACK)
                    .psh(PSH)
                    .rst(RST)
                    .syn(SYN)
                    .fin(FIN)
                    .window(window)
                    .urgentPointer(urgentPointer)
//                    .dataOffset((byte) 5)
                    .correctChecksumAtBuild(true)
                    .correctLengthAtBuild(true);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return builder;
    }

    /**
     * 获取用户输入，构建UDP报文
     * @param strDstAddr 目的地址
     * @param strSrcAddr 源地址
     * @return UdpPacket.Builder
     */
    private static UdpPacket.Builder udpPacketBuilder(String strDstAddr, String strSrcAddr) {
        UdpPacket.Builder builder = new UdpPacket.Builder();

        try {
            //获取用户输入
            System.out.println(">>>构建UDP报文");
            System.out.print("源端口地址 >");
            short srcPort = scanner.nextShort();
            System.out.print("目的端口地址 >");
            short dstPort = scanner.nextShort();
            scanner.nextLine(); //吸取回车
            System.out.println(">>>数据");
            byte[] payload =  scanner.nextLine().getBytes();
            if (payload.length != 0) {
                builder.payloadBuilder(new UnknownPacket.Builder().rawData(payload));
            }

            builder
                    .srcAddr(InetAddress.getByName(strSrcAddr))
                    .dstAddr(InetAddress.getByName(strDstAddr))
                    .srcPort(UdpPort.getInstance(srcPort))
                    .dstPort(UdpPort.getInstance(dstPort))
                    .correctChecksumAtBuild(true)
                    .correctLengthAtBuild(true);
            
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return builder;
    }

    private static ShitPacket.Builder shitPacketBuilder() {
        ShitPacket.Builder builder = new ShitPacket.Builder();

        try {

            //获取用户输入
            System.out.println(">>>构建自定义报文");
            System.out.print("协议类型 >");
            int shit = scanner.nextInt();
            System.out.print("质量 >");
            short quality = scanner.nextShort();
            System.out.print("目标状态 >");
            int dstStatus = scanner.nextInt();
            System.out.print("源状态 >");
            int srcStatus = scanner.nextInt();
            System.out.print("详细信息 >");
            scanner.nextLine();//吸取回车
            String details = scanner.nextLine();

            builder
                    .shit((byte) shit)
                    .quality(quality)
                    .dstStatus((byte) dstStatus)
                    .srcStatus((byte) srcStatus)
                    .details(details);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return builder;
    }
}
