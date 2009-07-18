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
    
    private boolean closed;
    private boolean eof;
    
    public ChannelInputStream(Window localWindow)
    {
        this.localWindow = localWindow;
    }
    
    @Override
    public synchronized int read() throws IOException
    {
        while (!(buf.available() > 0) && !eof && !closed)
            try {
                wait();
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
    
    public synchronized void receive(byte[] data, int offset, int len) throws TransportException
    {
        buf.putRawBytes(data, offset, len);
        notifyAll();
        localWindow.consumeAndCheck(len);
    }
    
    synchronized void setClosed()
    {
        closed = true;
        notifyAll();
    }
    
    synchronized void setEOF()
    {
        eof = true;
        notifyAll();
    }
    
}
