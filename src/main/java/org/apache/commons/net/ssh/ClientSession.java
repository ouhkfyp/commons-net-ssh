package org.apache.commons.net.ssh;

import java.io.InterruptedIOException;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.util.concurrent.SynchronousQueue;

import org.apache.commons.net.SocketClient;
import org.apache.commons.net.ssh.util.Buffer;

public class ClientSession extends SocketClient implements Runnable
{
    String username;
    SynchronousQueue<ByteBuffer> outPackets = new SynchronousQueue<ByteBuffer>();
    
    public boolean authPassword(String password)
    {
        return false;
    }
    
    public boolean authPublickey(KeyPair[] keypairs)
    {
        return false;
    }
    
    private ByteBuffer encode(Buffer buf)
    {
        
        return null;
    }
    
    public void run()
    {
        while (true)
        {
            // * take from outPackets and write to server
            // * for packets from server
            //   - will be either packets to be handled in this thread's context immediately e.g. key reexchange
            //   - data for a specific channel: will be written to its inputstream
            // * on session close -- close events go to the channels' streams (?)
        }
    }
    
    public synchronized void send(Buffer payload) throws InterruptedIOException
    {
        try
        {
            outPackets.put(encode(payload));
        }
        catch (InterruptedException e)
        {
            InterruptedIOException ioe = new InterruptedIOException();
            ioe.initCause(e);
            throw ioe;
        }
    }
    
    public void setUsername(String username)
    {
        this.username = username;
    }
    
}
