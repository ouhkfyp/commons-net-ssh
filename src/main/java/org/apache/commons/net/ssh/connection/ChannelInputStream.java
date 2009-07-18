package org.apache.commons.net.ssh.connection;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;

import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Buffer.BufferException;

public class ChannelInputStream extends InputStream
{
    
    private final Buffer buf = new Buffer();
    private final Window localWindow;
    
    private volatile boolean closed;
    private volatile boolean eof;
    
    public ChannelInputStream(Window localWindow)
    {
        this.localWindow = localWindow;
    }
    
    @Override
    public int read() throws IOException
    {
        synchronized (buf) {
            while (!(buf.available() > 0) && !eof && !closed)
                try {
                    buf.wait();
                } catch (InterruptedException e) {
                    throw (IOException) new InterruptedIOException().initCause(e);
                }
            try {
                return buf.getByte();
            } catch (BufferException e) {
                if (eof)
                    return -1;
                else if (closed)
                    throw new IOException("Stream closed");
                else
                    throw e;
            }
        }
    }
    
    public void receive(byte[] data, int offset, int len) throws TransportException
    {
        synchronized (buf) {
            buf.putRawBytes(data, offset, len);
            buf.notifyAll();
        }
        localWindow.consumeAndCheck(len);
    }
    
    void setClosed()
    {
        closed = true;
        synchronized (buf) {
            buf.notifyAll();
        }
    }
    
    void setEOF()
    {
        eof = true;
        synchronized (buf) {
            buf.notifyAll();
        }
    }
    
}
