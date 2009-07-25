package org.apache.commons.net.ssh.util;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class Pipe extends Thread
{
    
    public interface EOFCallback
    {
        void hadEOF();
    }
    
    public interface ErrorCallback
    {
        void hadIOException(IOException e);
    }
    
    public static EOFCallback closeOnEOFCallback(final Closeable closable)
    {
        return new EOFCallback()
            {
                
                public void hadEOF()
                {
                    IOUtils.closeQuietly(closable);
                }
            };
    }
    
    public static ErrorCallback closeOnErrorCallback(final Closeable closable)
    {
        return new ErrorCallback()
            {
                
                public void hadIOException(IOException ioe)
                {
                    IOUtils.closeQuietly(closable);
                }
            };
    }
    
    protected final InputStream in;
    
    protected final OutputStream out;
    protected int bufSize = 1;
    
    protected ErrorCallback errCB;
    
    protected EOFCallback eofCB;
    
    public Pipe(InputStream in, OutputStream out)
    {
        this(in, out, true);
    }
    
    public Pipe(InputStream in, OutputStream out, boolean daemon)
    {
        this.in = in;
        this.out = out;
        setName("pipe");
        setDaemon(daemon);
    }
    
    public void bufSize(int size)
    {
        bufSize = size;
    }
    
    public void eofCallback(EOFCallback cb)
    {
        eofCB = cb;
    }
    
    public void errorCallback(ErrorCallback cb)
    {
        errCB = cb;
    }
    
    @Override
    public void run()
    {
        byte[] buf = new byte[bufSize];
        int len;
        try {
            while ((len = in.read(buf)) != -1) {
                out.write(buf, 0, len);
                out.flush();
            }
            if (eofCB != null)
                eofCB.hadEOF();
        } catch (IOException ioe) {
            if (errCB != null)
                errCB.hadIOException(ioe);
        }
    }
    
}
