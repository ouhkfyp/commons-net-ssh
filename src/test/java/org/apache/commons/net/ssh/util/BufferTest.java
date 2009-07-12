package org.apache.commons.net.ssh.util;

import static org.junit.Assert.*;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;

import org.apache.commons.net.ssh.util.Buffer.BufferException;
import org.apache.commons.net.ssh.util.Constants.Message;
import org.junit.Before;
import org.junit.Test;

/**
 * Sample unit test for testing {@link Buffer} functionality
 * 
 * @author rorywinston
 * 
 */
public class BufferTest
{
    private Buffer posBuf;
    private Buffer buf;
    
    @Before()
    public void setUp() throws UnsupportedEncodingException, GeneralSecurityException
    {
        // for position test
        byte[] data = "Hello".getBytes("UTF-8");
        posBuf = new Buffer(data);
    }
    
    @Test
    public void testCommand()
    {
        // message identifier
        assertEquals(buf.putCommand(Message.IGNORE).getCommand(), Message.IGNORE);
    }
    
    @Test
    public void testDataTypes()
    {
        // bool
        assertEquals(buf.putBoolean(true).getBoolean(), true);
        
        // byte
        assertEquals(buf.putByte((byte) 10).getByte(), (byte) 10);
        
        // byte array
        assertArrayEquals(buf.putBytes("some string".getBytes()).getBytes(), "some string".getBytes());
        
        // mpint
        BigInteger bi = new BigInteger("1111111111111111111111111111111");
        assertEquals(buf.putMPInt(bi).getMPInt(), bi);
        
        // string
        assertEquals(buf.putString("some string").getString(), "some string");
        
        // uint32
        assertEquals(buf.putUInt(0xffffffffL).getUInt(), 0xffffffffL);
    }
    
    @Test
    public void testPassword()
    {
        char[] pass = "lolcatz".toCharArray();
        // test if put correctly as a string
        assertEquals(new Buffer().putPassword(pass).getString(), "lolcatz");
        // test that char[] was blanked out
        assertArrayEquals(pass, "       ".toCharArray());
    }
    
    @Test
    public void testPosition() throws UnsupportedEncodingException
    {
        assertEquals(5, posBuf.wpos());
        assertEquals(0, posBuf.rpos());
        assertEquals(5, posBuf.available());
        // read some bytes
        byte b = posBuf.getByte();
        assertEquals(b, (byte) 'H');
        assertEquals(1, posBuf.rpos());
        assertEquals(4, posBuf.available());
    }
    
    @Test
    public void testPublickey()
    {
        // TODO stub
    }
    
    @Test
    public void testSignature()
    {
        // TODO stub
    }
    
    @Test(expected = BufferException.class)
    public void testUnderflow()
    {
        // exhaust the buffer
        for (int i = 0; i < 5; ++i)
            posBuf.getByte();
        // underflow
        posBuf.getByte();
    }
    
}
