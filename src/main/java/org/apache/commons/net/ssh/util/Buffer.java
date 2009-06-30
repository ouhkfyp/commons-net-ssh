/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
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

import org.apache.commons.net.ssh.SSHRuntimeException;
import org.apache.commons.net.ssh.Constants.KeyType;
import org.apache.commons.net.ssh.Constants.Message;

/**
 * Facilitates reading and writing SSH packets
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
 */
public final class Buffer
{
    
    public static class BufferException extends RuntimeException
    {
        public BufferException(String message)
        {
            super(message);
        }
    }
    
    public static final int DEFAULT_SIZE = 256;
    
    private static int getNextPowerOf2(int i)
    {
        int j = 1;
        while (j < i)
            j <<= 1;
        return j;
    }
    
    private byte[] data;
    
    private int rpos;
    
    private int wpos;
    
    public Buffer()
    {
        this(DEFAULT_SIZE);
    }
    
    public Buffer(byte[] data)
    {
        this(data, true);
    }
    
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
    
    /**
     * Constructs new buffer for the specified SSH packet and reserves the needed space (5 bytes)
     * for the packet header.
     * 
     * @param cmd
     *            the SSH command
     */
    public Buffer(Message cmd)
    {
        this();
        rpos = wpos = 5;
        putByte(cmd.toByte());
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
    
    public void compact()
    {
        if (available() > 0)
            System.arraycopy(data, rpos, data, 0, wpos - rpos);
        wpos -= rpos;
        rpos = 0;
    }
    
    private void ensureAvailable(int a)
    {
        if (available() < a)
            throw new BufferException("Underflow");
    }
    
    private void ensureCapacity(int capacity)
    {
        if (data.length - wpos < capacity) {
            int cw = wpos + capacity;
            byte[] tmp = new byte[getNextPowerOf2(cw)];
            System.arraycopy(data, 0, tmp, 0, data.length);
            data = tmp;
        }
    }
    
    public boolean getBoolean()
    {
        return getByte() != 0;
    }
    
    public byte getByte()
    {
        ensureAvailable(1);
        return data[rpos++];
    }
    
    public byte[] getBytes()
    {
        int len = getInt();
        if (len < 0 || len > 32768)
            throw new IllegalStateException("Bad item length: " + len);
        byte[] b = new byte[len];
        getRawBytes(b);
        return b;
    }
    
    /*
     * ====================== Read methods ======================
     */

    public Message getCommand()
    {
        byte b = getByte();
        Message cmd = Message.fromByte(b);
        if (cmd == null)
            throw new IllegalStateException("Unknown command code: " + b);
        return cmd;
    }
    
    public byte[] getCompactData()
    {
        int l = available();
        if (l > 0) {
            byte[] b = new byte[l];
            System.arraycopy(data, rpos, b, 0, l);
            return b;
        } else
            return new byte[0];
    }
    
    public int getInt()
    {
        ensureAvailable(4);
        int i = data[rpos++] << 24 & 0xff000000 | data[rpos++] << 16 & 0x00ff0000
                | data[rpos++] << 8 & 0x0000ff00 | data[rpos++] & 0x000000ff;
        return i;
    }
    
    public LQString getLanguageQualifiedField()
    {
        return new LQString(getString(), getString());
    }
    
    public BigInteger getMPInt()
    {
        return new BigInteger(getMPIntAsBytes());
    }
    
    public byte[] getMPIntAsBytes()
    {
        return getBytes();
    }
    
    public PublicKey getPublicKey()
    {
        PublicKey key = null;
        try {
            switch (KeyType.fromString(getString()))
            {
            case RSA:
            {
                BigInteger e = getMPInt();
                BigInteger n = getMPInt();
                KeyFactory keyFactory = SecurityUtils.getKeyFactory("RSA");
                key = keyFactory.generatePublic(new RSAPublicKeySpec(n, e));
                break;
            }
            case DSA:
            {
                BigInteger p = getMPInt();
                BigInteger q = getMPInt();
                BigInteger g = getMPInt();
                BigInteger y = getMPInt();
                KeyFactory keyFactory = SecurityUtils.getKeyFactory("DSA");
                key = keyFactory.generatePublic(new DSAPublicKeySpec(y, p, q, g));
                break;
            }
            default:
                assert false;
            }
        } catch (GeneralSecurityException e) {
            throw new SSHRuntimeException(e);
        }
        return key;
    }
    
    public void getRawBytes(byte[] buf)
    {
        getRawBytes(buf, 0, buf.length);
    }
    
    public void getRawBytes(byte[] buf, int off, int len)
    {
        ensureAvailable(len);
        System.arraycopy(data, rpos, buf, off, len);
        rpos += len;
    }
    
    public String getString()
    {
        int len = getInt();
        if (len < 0 || len > 32768)
            throw new IllegalStateException("Bad item length: " + len);
        ensureAvailable(len);
        String s = null;
        try {
            s = new String(data, rpos, len, "UTF-8");
        } catch (UnsupportedEncodingException e) {
        }
        rpos += len;
        return s;
    }
    
    public byte[] getStringAsBytes()
    {
        return getBytes();
    }
    
    public String printHex()
    {
        return BufferUtils.printHex(array(), rpos(), available());
    }
    
    public void putBoolean(boolean b)
    {
        putByte(b ? (byte) 1 : (byte) 0);
    }
    
    public void putBuffer(Buffer buffer)
    {
        int r = buffer.available();
        ensureCapacity(r);
        System.arraycopy(buffer.data, buffer.rpos, data, wpos, r);
        wpos += r;
    }
    
    /*
     * ====================== Write methods ======================
     */

    public void putByte(byte b)
    {
        ensureCapacity(1);
        data[wpos++] = b;
    }
    
    public void putBytes(byte[] b)
    {
        putBytes(b, 0, b.length);
    }
    
    public void putBytes(byte[] b, int off, int len)
    {
        putInt(len);
        ensureCapacity(len);
        System.arraycopy(b, off, data, wpos, len);
        wpos += len;
    }
    
    public void putCommand(Message cmd)
    {
        putByte(cmd.toByte());
    }
    
    public void putInt(int i)
    {
        ensureCapacity(4);
        data[wpos++] = (byte) (i >> 24);
        data[wpos++] = (byte) (i >> 16);
        data[wpos++] = (byte) (i >> 8);
        data[wpos++] = (byte) i;
    }
    
    public void putMPInt(BigInteger bi)
    {
        putMPInt(bi.toByteArray());
    }
    
    public void putMPInt(byte[] foo)
    {
        int i = foo.length;
        if ((foo[0] & 0x80) != 0) {
            i++;
            putInt(i);
            putByte((byte) 0);
        } else
            putInt(i);
        putRawBytes(foo);
    }
    
    public void putPublicKey(PublicKey key)
    {
        KeyType type;
        switch (type = KeyType.fromKey(key))
        {
        case RSA:
            putString(type.toString());
            putMPInt(((RSAPublicKey) key).getPublicExponent());
            putMPInt(((RSAPublicKey) key).getModulus());
            break;
        case DSA:
            putString(type.toString());
            putMPInt(((DSAPublicKey) key).getParams().getP());
            putMPInt(((DSAPublicKey) key).getParams().getQ());
            putMPInt(((DSAPublicKey) key).getParams().getG());
            putMPInt(((DSAPublicKey) key).getY());
            break;
        default:
            assert false;
        }
    }
    
    public void putRawBytes(byte[] d)
    {
        putRawBytes(d, 0, d.length);
    }
    
    public void putRawBytes(byte[] d, int off, int len)
    {
        ensureCapacity(len);
        System.arraycopy(d, off, data, wpos, len);
        wpos += len;
    }
    
    public void putString(byte[] str)
    {
        putInt(str.length);
        putRawBytes(str);
    }
    
    public void putString(char[] str)
    {
        byte[] asBytes = new byte[str.length];
        for (int i = 0; i < str.length; i++)
            asBytes[i] = (byte) str[i];
        putString(asBytes);
    }
    
    public void putString(String string)
    {
        putString(string.getBytes());
    }
    
    public int rpos()
    {
        return rpos;
    }
    
    public void rpos(int rpos)
    {
        this.rpos = rpos;
    }
    
    @Override
    public String toString()
    {
        return "Buffer [rpos=" + rpos + ", wpos=" + wpos + ", size=" + data.length + "]";
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
    
}
