package org.apache.commons.net.ssh.util;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

import org.apache.commons.net.ssh.SSHPacket;
import org.apache.commons.net.ssh.SSHRuntimeException;
import org.apache.commons.net.ssh.util.Constants.KeyType;

public class Buffer<T extends Buffer<T>>
{
    
    public static class PlainBuffer extends Buffer<PlainBuffer>
    {
        
        public PlainBuffer()
        {
            super();
        }
        
        public PlainBuffer(byte[] b)
        {
            super(b);
        }
        
        public PlainBuffer(int size)
        {
            super(size);
        }
    }
    
    public static class BufferException extends SSHRuntimeException
    {
        public BufferException(String message)
        {
            super(message);
        }
    }
    
    /**
     * The default size for a {@code Buffer} (256 bytes)
     */
    public static final int DEFAULT_SIZE = 256;
    
    protected static int getNextPowerOf2(int i)
    {
        int j = 1;
        while (j < i)
            j <<= 1;
        return j;
    }
    
    protected byte[] data;
    protected int rpos;
    protected int wpos;
    
    /**
     * @see {@link #DEFAULT_SIZE}
     */
    public Buffer()
    {
        this(DEFAULT_SIZE);
    }
    
    public Buffer(Buffer<T> from)
    {
        data = new byte[(wpos = from.wpos - from.rpos)];
        System.arraycopy(from.data, from.rpos, data, 0, wpos);
    }
    
    /**
     * @param data
     *            byte-array to initialise with
     */
    public Buffer(byte[] data)
    {
        this(data, true);
    }
    
    /**
     * @param data
     *            byte-array to initialise with
     * @param read
     *            whether write position should be advanced
     * 
     */
    public Buffer(byte[] data, boolean read)
    {
        this.data = data;
        rpos = 0;
        wpos = read ? data.length : 0;
    }
    
    public Buffer(int size)
    {
        this(new byte[getNextPowerOf2(size)], false);
    }
    
    public byte[] array()
    {
        return data;
    }
    
    public int available()
    {
        return wpos - rpos;
    }
    
    /**
     * Resets this buffer. The object becomes ready for reuse.
     */
    public void clear()
    {
        rpos = 0;
        wpos = 0;
    }
    
    public int rpos()
    {
        return rpos;
    }
    
    public void rpos(int rpos)
    {
        this.rpos = rpos;
    }
    
    public int wpos()
    {
        return wpos;
    }
    
    public void wpos(int wpos)
    {
        ensureCapacity(wpos - this.wpos);
        this.wpos = wpos;
    }
    
    protected void ensureAvailable(int a)
    {
        if (available() < a)
            throw new BufferException("Underflow");
    }
    
    public void ensureCapacity(int capacity)
    {
        if (data.length - wpos < capacity)
        {
            int cw = wpos + capacity;
            byte[] tmp = new byte[getNextPowerOf2(cw)];
            System.arraycopy(data, 0, tmp, 0, data.length);
            data = tmp;
        }
    }
    
    /**
     * Compact this {@link SSHPacket}
     */
    public void compact()
    {
        System.err.println("COMPACTING");
        if (available() > 0)
            System.arraycopy(data, rpos, data, 0, wpos - rpos);
        wpos -= rpos;
        rpos = 0;
    }
    
    public byte[] getCompactData()
    {
        int len = available();
        if (len > 0)
        {
            byte[] b = new byte[len];
            System.arraycopy(data, rpos, b, 0, len);
            return b;
        } else
            return new byte[0];
    }
    
    /**
     * Read an SSH boolean byte
     * 
     * @return the {@code true} or {@code false} value read
     */
    public boolean readBoolean()
    {
        return readByte() != 0;
    }
    
    /**
     * Puts an SSH boolean value
     * 
     * @param b
     *            the value
     * @return this
     */
    public T putBoolean(boolean b)
    {
        return putByte(b ? (byte) 1 : (byte) 0);
    }
    
    /**
     * Read a byte from the buffer
     * 
     * @return the byte read
     */
    public byte readByte()
    {
        ensureAvailable(1);
        return data[rpos++];
    }
    
    /**
     * Writes a single byte into this buffer
     * 
     * @param b
     * @return this
     */
    @SuppressWarnings("unchecked")
    public T putByte(byte b)
    {
        ensureCapacity(1);
        data[wpos++] = b;
        return (T) this;
    }
    
    /**
     * Read an SSH byte-array
     * 
     * @return the byte-array read
     */
    public byte[] readBytes()
    {
        int len = readInt();
        if (len < 0 || len > 32768)
            throw new BufferException("Bad item length: " + len);
        byte[] b = new byte[len];
        readRawBytes(b);
        return b;
    }
    
    /**
     * Writes Java byte-array as an SSH byte-array
     * 
     * @param b
     *            Java byte-array
     * @return this
     */
    public T putBytes(byte[] b)
    {
        return putBytes(b, 0, b.length);
    }
    
    /**
     * Writes Java byte-array as an SSH byte-array
     * 
     * @param b
     *            Java byte-array
     * @param off
     *            offset
     * @param len
     *            length
     * @return this
     */
    public T putBytes(byte[] b, int off, int len)
    {
        return putInt(len - off).putRawBytes(b, off, len);
    }
    
    public void readRawBytes(byte[] buf)
    {
        readRawBytes(buf, 0, buf.length);
    }
    
    public void readRawBytes(byte[] buf, int off, int len)
    {
        ensureAvailable(len);
        System.arraycopy(data, rpos, buf, off, len);
        rpos += len;
    }
    
    public T putRawBytes(byte[] d)
    {
        return putRawBytes(d, 0, d.length);
    }
    
    @SuppressWarnings("unchecked")
    public T putRawBytes(byte[] d, int off, int len)
    {
        ensureCapacity(len);
        System.arraycopy(d, off, data, wpos, len);
        wpos += len;
        return (T) this;
    }
    
    /**
     * Copies the contents of provided buffer into this buffer
     * 
     * @param buffer
     *            the {@code Buffer} to copy
     * @return this
     */
    @SuppressWarnings("unchecked")
    public T putBuffer(Buffer<? extends Buffer<?>> buffer)
    {
        if (buffer != null)
        {
            int r = buffer.available();
            ensureCapacity(r);
            System.arraycopy(buffer.data, buffer.rpos, data, wpos, r);
            wpos += r;
        }
        return (T) this;
    }
    
    public int readInt()
    {
        return (int) readLong();
    }
    
    public long readLong()
    {
        ensureAvailable(4);
        long i = data[rpos++] << 24 & 0xff000000L // 
                | data[rpos++] << 16 & 0x00ff0000L //
                | data[rpos++] << 8 & 0x0000ff00L //
                | data[rpos++] & 0x000000ffL;
        return i;
    }
    
    /**
     * Writes a uint32 integer
     * 
     * @param uint32
     * @return this
     */
    @SuppressWarnings("unchecked")
    public T putInt(long uint32)
    {
        ensureCapacity(4);
        if (uint32 < 0 || uint32 > 0xffffffffL)
            throw new BufferException("Invalid value: " + uint32);
        data[wpos++] = (byte) (uint32 >> 24);
        data[wpos++] = (byte) (uint32 >> 16);
        data[wpos++] = (byte) (uint32 >> 8);
        data[wpos++] = (byte) uint32;
        return (T) this;
    }
    
    /**
     * Read an SSH multiple-precision integer
     * 
     * @return the MP integer as a {@code BigInteger}
     */
    public BigInteger readMPInt()
    {
        return new BigInteger(readMPIntAsBytes());
    }
    
    /**
     * Writes an SSH multiple-precision integer from a {@code BigInteger}
     * 
     * @param bi
     *            {@code BigInteger} to write
     * @return this
     */
    public T putMPInt(BigInteger bi)
    {
        return putMPInt(bi.toByteArray());
    }
    
    /**
     * Writes an SSH multiple-precision integer from a Java byte-array
     * 
     * @param foo
     *            byte-array
     * @return this
     */
    public T putMPInt(byte[] foo)
    {
        int i = foo.length;
        if ((foo[0] & 0x80) != 0)
        {
            i++;
            putInt(i);
            putByte((byte) 0);
        } else
            putInt(i);
        return putRawBytes(foo);
    }
    
    public byte[] readMPIntAsBytes()
    {
        return readBytes();
    }
    
    public long readUINT64()
    {
        long uint64 = (readLong() << 32) + (readLong() & 0xffffffffL);
        if (uint64 < 0)
            throw new BufferException("Cannot handle values > Long.MAX_VALUE");
        return uint64;
    }
    
    @SuppressWarnings("unchecked")
    public T putUINT64(long uint64)
    {
        if (uint64 < 0)
            throw new BufferException("Invalid value: " + uint64);
        data[wpos++] = (byte) (uint64 >> 56);
        data[wpos++] = (byte) (uint64 >> 48);
        data[wpos++] = (byte) (uint64 >> 40);
        data[wpos++] = (byte) (uint64 >> 32);
        data[wpos++] = (byte) (uint64 >> 24);
        data[wpos++] = (byte) (uint64 >> 16);
        data[wpos++] = (byte) (uint64 >> 8);
        data[wpos++] = (byte) uint64;
        return (T) this;
    }
    
    /**
     * Reads an SSH string
     * 
     * @return the string as a Java {@code String}
     */
    public String readString()
    {
        int len = readInt();
        if (len < 0 || len > 32768)
            throw new BufferException("Bad item length: " + len);
        ensureAvailable(len);
        String s = null;
        try
        {
            s = new String(data, rpos, len, "UTF-8");
        } catch (UnsupportedEncodingException e)
        {
            throw new SSHRuntimeException(e);
        }
        rpos += len;
        return s;
    }
    
    /**
     * Reads an SSH string
     * 
     * @return the string as a byte-array
     */
    public byte[] readStringAsBytes()
    {
        return readBytes();
    }
    
    public T putString(byte[] str)
    {
        return putBytes(str);
    }
    
    public T putString(byte[] str, int offset, int len)
    {
        return putBytes(str, offset, len);
    }
    
    public T putString(String string)
    {
        try
        {
            return putString(string.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e)
        {
            throw new SSHRuntimeException(e);
        }
    }
    
    /**
     * Writes a char-array as an SSH string and then blanks it out.
     * 
     * This is useful when a plaintext password needs to be sent. If {@code passwd} is {@code null}, an empty string is
     * written.
     * 
     * @param passwd
     *            (null-ok) the password as a character array
     * @return this
     */
    @SuppressWarnings("unchecked")
    public T putPassword(char[] passwd)
    {
        if (passwd == null)
            return putString("");
        putInt(passwd.length);
        ensureCapacity(passwd.length);
        for (char c : passwd)
            data[wpos++] = (byte) c;
        Arrays.fill(passwd, ' ');
        return (T) this;
    }
    
    public PublicKey readPublicKey()
    {
        PublicKey key = null;
        try
        {
            switch (KeyType.fromString(readString()))
            {
            case RSA:
            {
                BigInteger e = readMPInt();
                BigInteger n = readMPInt();
                KeyFactory keyFactory = SecurityUtils.getKeyFactory("RSA");
                key = keyFactory.generatePublic(new RSAPublicKeySpec(n, e));
                break;
            }
            case DSA:
            {
                BigInteger p = readMPInt();
                BigInteger q = readMPInt();
                BigInteger g = readMPInt();
                BigInteger y = readMPInt();
                KeyFactory keyFactory = SecurityUtils.getKeyFactory("DSA");
                key = keyFactory.generatePublic(new DSAPublicKeySpec(y, p, q, g));
                break;
            }
            default:
                assert false;
            }
        } catch (GeneralSecurityException e)
        {
            throw new SSHRuntimeException(e);
        }
        return key;
    }
    
    @SuppressWarnings("unchecked")
    public T putPublicKey(PublicKey key)
    {
        KeyType type = KeyType.fromKey(key);
        switch (type)
        {
        case RSA:
            putString(type.toString()) // ssh-rsa
                    .putMPInt(((RSAPublicKey) key).getPublicExponent()) // e
                    .putMPInt(((RSAPublicKey) key).getModulus()); // n
            break;
        case DSA:
            putString(type.toString()) // ssh-dss
                    .putMPInt(((DSAPublicKey) key).getParams().getP()) // p
                    .putMPInt(((DSAPublicKey) key).getParams().getQ()) // q
                    .putMPInt(((DSAPublicKey) key).getParams().getG()) // g
                    .putMPInt(((DSAPublicKey) key).getY()); // y
            break;
        default:
            assert false;
        }
        return (T) this;
    }
    
    public T putSignature(String sigFormat, byte[] sigData)
    {
        return putString(new Buffer<T>() // signature blob as string
                .putString(sigFormat) // sig format identifier
                .putBytes(sigData) // sig as byte array
                .getCompactData());
    }
    
    /**
     * Gives a readable snapshot of the buffer in hex. This is useful for debugging.
     * 
     * @return snapshot of the buffer as a hex string with each octet delimited by a space
     */
    public String printHex()
    {
        return BufferUtils.printHex(array(), rpos(), available());
    }
    
    @Override
    public String toString()
    {
        return "Buffer [rpos=" + rpos + ", wpos=" + wpos + ", size=" + data.length + "]";
    }
    
}
