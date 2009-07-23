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
        eof();
    }
    
    public void eof()
    {
        synchronized (buf) {
            if (!eof) {
                eof = true;
                buf.notifyAll();
            }
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
            avail = win.getInitialSize() - buf.available();
        }
        win.check(avail);
        return len;
    }
    
    public void receive(byte[] data, int offset, int len) throws ConnectionException, TransportException
    {
        synchronized (buf) {
            if (eof)
                throw new ConnectionException("Getting data on EOF'ed stream");
            buf.putRawBytes(data, offset, len);
            buf.notifyAll();
        }
        win.consume(len);
    }
    
}
