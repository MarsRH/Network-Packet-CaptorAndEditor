package org.networkdesign;

import org.pcap4j.packet.AbstractPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.ByteArrays;

import java.util.*;
import java.util.function.Consumer;

/**
 * 自定义网络协议
 */
public class ShitPacket extends AbstractPacket {

    private static final long serialVersionUID = 8001811020717409437L;

    private final ShitHeader header;

    public static ShitPacket newPacket(byte[] rawData, int offset, int length)
            throws IllegalRawDataException {
        ByteArrays.validateBounds(rawData, offset, length);
        return new ShitPacket(rawData, offset, length);
    }


    private ShitPacket(byte[] rawData, int offset, int length) throws IllegalRawDataException {
        this.header = new ShitHeader(rawData, offset, length);
    }

    //构造函数
    ShitPacket(Builder builder) {
        if (builder == null) {

            throw new NullPointerException("builder: " + builder);
        }
        this.header = new ShitHeader(builder);
    }

    /**
     * 自定义协议构造器
     * Builder
     */
    public static final class Builder extends AbstractBuilder {
        private byte shit;
        private short length;
        private short quality;
        private byte dstStatus;
        private byte srcStatus;
        private int details;

        //无参构造函数
        public Builder() {}
        //带参构造函数
        public Builder(ShitPacket packet) {

            this.shit = packet.header.shit;
            this.length = packet.header.length;
            this.quality = packet.header.quality;
            this.dstStatus = packet.header.dstStatus;
            this.srcStatus = packet.header.srcStatus;
            this.details = packet.header.details;
        }
        //用于设置报头参数的方法
        /**
         * 0:V1 | 1:V2 | 2:V3 | 3:V4
         * @param shit 协议类型
         */
        public Builder shit(byte shit) {
            this.shit = shit;
            return this;
        }

        /**
         * @param length 头部长度
         */
        public Builder length(short length) {
            this.length = length;
            return this;
        }

        /**
         * 0~255
         * @param quality 质量
         */
        public Builder quality(short quality) {
            this.quality = quality;
            return this;
        }

        /**
         * @param dstStatus 目标状态
         */
        public Builder dstStatus(byte dstStatus) {
            this.dstStatus = dstStatus;
            return this;
        }

        /**
         * @param srcStatus 源状态
         */
        public Builder srcStatus(byte srcStatus) {
            this.srcStatus = srcStatus;
            return this;
        }

        /**
         * @param details 详细信息
         */
        public void details(String details) {
            if (details.isEmpty()) {
                return;
            } else if (details.length() < ShitHeader.DETAILS_SIZE) {
                details += "    ";
            }
            this.details = ByteArrays.getInt(details.getBytes(), 0);
        }

        @Override
        public Packet build() {
            return new ShitPacket(this);
        }
    }

    /**
     * 自定义报文头部
     * Header
     */
    public static final class ShitHeader extends AbstractHeader {

        private static final long serialVersionUID = -3402714274558629209L;
        private static final int SHIT_OFFSET = 0;
        private static final int SHIT_SIZE = 1;
        private static final int LENGTH_OFFSET = SHIT_OFFSET + SHIT_SIZE;
        private static final int LENGTH_SIZE = 2;
        private static final int QUALITY_OFFSET = LENGTH_OFFSET + LENGTH_SIZE;
        private static final int QUALITY_SIZE = 2;
        private static final int DSTSTATUS_OFFSET = QUALITY_OFFSET + QUALITY_SIZE;
        private static final int DSTSTATUS_SIZE = 1;
        private static final int SRCSTATUS_OFFSET = DSTSTATUS_OFFSET + DSTSTATUS_SIZE;
        private static final int SRCSTATUS_SIZE = 1;
        private static final int DETAILS_OFFSET = SRCSTATUS_OFFSET + SRCSTATUS_SIZE;
        private static final int DETAILS_SIZE = 4;
        private static final int SHIT_HEADER_SIZE = DETAILS_OFFSET + DETAILS_SIZE;

        private final byte shit;    //协议类型
        private final short length; // 总长度
        private final short quality; //质量
        private final byte dstStatus; //目标状态
        private final byte srcStatus; //源状态
        private final int details; //详细信息


        //构造函数
        ShitHeader(byte[] rawData, int offset, int length) throws IllegalRawDataException {
            this.shit = ByteArrays.getByte(rawData, SHIT_OFFSET + offset);
            this.length = ByteArrays.getShort(rawData, LENGTH_OFFSET + offset);
            this.quality = ByteArrays.getShort(rawData, QUALITY_OFFSET + offset);
            this.dstStatus = ByteArrays.getByte(rawData, DSTSTATUS_OFFSET + offset);
            this.srcStatus = ByteArrays.getByte(rawData, SRCSTATUS_OFFSET + offset);
            this.details = ByteArrays.getInt(rawData,DETAILS_OFFSET + offset);
        }
        //构造函数
        private ShitHeader(Builder builder) {
            this.shit = builder.shit;
            this.quality = builder.quality;
            this.dstStatus = builder.dstStatus;
            this.srcStatus = builder.srcStatus;
            this.details = builder.details;
            this.length = builder.length;
        }
        //获取报头数据相关方法
        /**
         * @return shit 协议类型
         */
        public String getShit() {
            String s = String.valueOf(shit);
            switch (shit){
                case 0:
                    s += " (V1)";
                    break;
                case 1:
                    s += " (V2)";
                    break;
                case 2:
                    s += " (V3)";
                    break;
                case 3:
                    s += " (V4)";
                    break;
                default:
                    s += " (Unknown)";
            }
            return s;
        }

        /**
         * @return length 头部长度
         */
        public short getLength() {
            return (short) Math.max(SHIT_HEADER_SIZE, length);
        }

        /**
         * @return quality 质量
         */
        public short getQuality() {
            return quality;
        }

        /**
         * @return dstStatus 目标状态
         */
        public byte getDstStatus() {
            return dstStatus;
        }

        /**
         * @return srcStatus 源质量
         */
        public byte getSrcStatus() {
            return srcStatus;
        }

        /**
         * @return details 详细信息
         */
        public String getDetails() {
            return "[DETAILS]:\n"+ new String( ByteArrays.toByteArray(details));
        }

        /**
         * 用于发包的时候控制台输出信息,将包信息转化为字符串
         * @return String
         */
        protected String buildString() {
            StringBuilder sb = new StringBuilder();
            String ls = System.getProperty("line.separator");
            sb.append("[SHIT Header (").append(this.length()).append(" bytes)]").append(ls);
            sb.append("  Shit: ").append(this.getShit()).append(ls);
            sb.append("  Length: ").append(this.getLength()).append(" [bytes]").append(ls);
            sb.append("  Quality: ").append(this.getQuality()).append(ls);
            sb.append("  Destination Status: ").append(this.getDstStatus()).append(ls);
            sb.append("  Source Status: ").append(this.getSrcStatus()).append(ls);
            sb.append("  Details: ").append(new String( ByteArrays.toByteArray(this.details))).append(ls);
            return sb.toString();
        }

        @Override
        protected List<byte[]> getRawFields() {
            List<byte[]> rawFields = new ArrayList<byte[]>();
            rawFields.add(ByteArrays.toByteArray(shit));
            rawFields.add(ByteArrays.toByteArray(length));
            rawFields.add(ByteArrays.toByteArray(quality));
            rawFields.add(ByteArrays.toByteArray(dstStatus));
            rawFields.add(ByteArrays.toByteArray(srcStatus));
            rawFields.add(ByteArrays.toByteArray(details));
            return rawFields;
        }
    }

    //获取Builder与Header的方法
    @Override
    public Builder getBuilder() {
        return new Builder(this);
    }

    @Override
    public ShitHeader getHeader() {
        return header;
    }

    //基础类方法
    @Override
    public Iterator<Packet> iterator() {
        return super.iterator();
    }

    @Override
    public void forEach(Consumer<? super Packet> action) {
        super.forEach(action);
    }

    @Override
    public Spliterator<Packet> spliterator() {
        return super.spliterator();
    }

    @Override
    public <T extends Packet> T get(Class<T> clazz) {
        return super.get(clazz);
    }

    @Override
    public Packet getLowerLayerOf(Class<? extends Packet> clazz) {
        return super.getLowerLayerOf(clazz);
    }

    @Override
    public <T extends Packet> boolean contains(Class<T> clazz) {
        return super.contains(clazz);
    }
}
