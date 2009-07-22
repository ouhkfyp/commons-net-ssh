package org.apache.commons.net.ssh.connection;

import java.util.Map;
import java.util.Map.Entry;

import org.apache.commons.net.ssh.util.Buffer;

/*
 * TODO painful 
 */
public enum PTYMode
{
    
    //    public static final byte TTY_OP_END = (byte) 0;
    //    public static final byte VINTR = (byte) 1;
    //    public static final byte VQUIT = (byte) 2;
    //    public static final byte VERASE = (byte) 3;
    //    public static final byte VKILL = (byte) 4;
    //    public static final byte VEOF = (byte) 5;
    //    public static final byte VEOL = (byte) 6;
    //    public static final byte VEOL2 = (byte) 7;
    //    public static final byte VSTART = (byte) 8;
    //    public static final byte VSTOP = (byte) 9;
    //    public static final byte VSUSP = (byte) 10;
    //    public static final byte VDSUSP = (byte) 11;
    //    public static final byte VREPRINT = (byte) 12;
    //    public static final byte VWERASE = (byte) 13;
    //    public static final byte VLNEXT = (byte) 14;
    //    public static final byte VFLUSH = (byte) 15;
    //    public static final byte VSWTCH = (byte) 16;
    //    public static final byte VSTATUS = (byte) 17;
    //    public static final byte VDISCARD = (byte) 18;
    //    public static final byte IGNPAR = (byte) 30;
    //    public static final byte PARMRK = (byte) 31;
    //    public static final byte INPCK = (byte) 32;
    //    public static final byte ISTRIP = (byte) 33;
    //    public static final byte INLCR = (byte) 34;
    //    public static final byte IGNCR = (byte) 35;
    //    public static final byte ICRNL = (byte) 36;
    //    public static final byte IUCLC = (byte) 37;
    //    public static final byte IXON = (byte) 38;
    //    public static final byte IXANY = (byte) 39;
    //    public static final byte IXOFF = (byte) 40;
    //    public static final byte IMAXBEL = (byte) 41;
    //    public static final byte ISIG = (byte) 50;
    //    public static final byte ICANON = (byte) 51;
    //    public static final byte XCASE = (byte) 52;
    //    public static final byte ECHO = (byte) 53;
    //    public static final byte ECHOE = (byte) 54;
    //    public static final byte ECHOK = (byte) 55;
    //    public static final byte ECHONL = (byte) 56;
    //    public static final byte NOFLSH = (byte) 57;
    //    public static final byte TOSTOP = (byte) 58;
    //    public static final byte IEXTEN = (byte) 59;
    //    public static final byte ECHOCTL = (byte) 60;
    //    public static final byte ECHOKE = (byte) 61;
    //    public static final byte PENDIN = (byte) 62;
    //    public static final byte OPOST = (byte) 70;
    //    public static final byte OLCUC = (byte) 71;
    //    public static final byte ONLCR = (byte) 72;
    //    public static final byte OCRNL = (byte) 73;
    //    public static final byte ONOCR = (byte) 74;
    //    public static final byte ONLRET = (byte) 75;
    //    public static final byte CS7 = (byte) 90;
    //    public static final byte CS8 = (byte) 91;
    //    public static final byte PARENB = (byte) 92;
    //    public static final byte PARODD = (byte) 93;
    //    public static final byte TTY_OP_ISPEED = (byte) 128;
    //    public static final byte TTY_OP_OSPEED = (byte) 129;
    
    ISIG(50),
    ICANON(51),
    ECHO(53),
    ECHOE(54),
    ECHOK(55),
    ECHONL(56),
    NOFLSH(57);
    
    public static byte[] encode(Map<PTYMode, Integer> modes)
    {
        Buffer buf = new Buffer();
        for (Entry<PTYMode, Integer> entry : modes.entrySet()) {
            buf.putByte(entry.getKey().getOpcode());
            buf.putInt(entry.getValue());
        }
        buf.putByte((byte) 0);
        return buf.getCompactData();
    }
    
    private final byte opcode;
    
    private PTYMode(int opcode)
    {
        this.opcode = (byte) opcode;
    }
    
    public byte getOpcode()
    {
        return opcode;
    }
}