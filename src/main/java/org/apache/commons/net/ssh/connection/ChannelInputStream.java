package org.apache.commons.net.ssh.connection;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;

import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.util.Buffer;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @author shikhar
 */
public class ChannelInputStream extends InputStream
{
    
    private final Buffer buf = new Buffer();
    private final byte[] b = new byte[1];
    private final LocalWindow win;
    
    private boolean closed;
    private boolean eof;
    
    public ChannelInputStream(LocalWindow win)
    {
        this.win = win;
    }
    
    @Override
    public int available()
    {
        synchronized (buf) {
            return buf.available();
        }
    }
    
    @Override
    public void close()
    {
        synchronized (buf) {
            closed = true;
            buf.notifyAll();
        }
    }
    
    public void eof()
    {
        synchronized (buf) {
            eof = true;
            buf.notifyAll();
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
            if (buf.rpos() > win.getMaxPacketSize() || buf.available() == 0)
                buf.compact();
            avail = win.getMaxSize() - buf.available();
        }
        win.check(avail);
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
        win.consumeAndCheck(len);
    }
    
}
