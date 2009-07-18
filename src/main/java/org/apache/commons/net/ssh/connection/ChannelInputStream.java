package org.apache.commons.net.ssh.connection;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;

import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.util.Buffer;

public class ChannelInputStream extends InputStream
{
    
    private final Buffer buf = new Buffer();
    private final byte[] b = new byte[1];
    private final Window localWindow;
    
    private boolean closed;
    private boolean eof;
    
    public ChannelInputStream(Window localWindow)
    {
        this.localWindow = localWindow;
    }
    
    @Override
    public int available()
    {
        synchronized (buf) {
            return buf.available();
        }
    }
    
    @Override
    public int read() throws IOException
    {
        synchronized (b) {
            int l = read(b, 0, 1);
            if (l == -1)
                return -1;
            return b[0];
        }
    }
    
    @Override
    public int read(byte[] b, int off, int len) throws IOException
    {
        int avail;
        synchronized (buf) {
            for (;;) {
                if (eof)
                    return -1;
                if (closed)
                    throw new IOException("Pipe closed");
                if (buf.available() > 0)
                    break;
                try {
                    buf.wait();
                } catch (InterruptedException e) {
                    throw (IOException) new InterruptedIOException().initCause(e);
                }
            }
            if (len > buf.available())
                len = buf.available();
            buf.getRawBytes(b, off, len);
            if (buf.rpos() > localWindow.getPacketSize() || buf.available() == 0)
                buf.compact();
            avail = localWindow.getMaxSize() - buf.available();
        }
        localWindow.check(avail);
        return len;
    }
    
    public void receive(byte[] data, int offset, int len) throws ConnectionException, TransportException
    {
        synchronized (buf) {
            if (closed)
                throw new ConnectionException("Stream closed");
            buf.putRawBytes(data, offset, len);
            buf.notifyAll();
        }
        localWindow.consumeAndCheck(len);
    }
    
    void setClosed()
    {
        synchronized (buf) {
            closed = true;
            buf.notifyAll();
        }
    }
    
    void setEOF()
    {
        synchronized (buf) {
            eof = true;
            buf.notifyAll();
        }
    }
    
}
