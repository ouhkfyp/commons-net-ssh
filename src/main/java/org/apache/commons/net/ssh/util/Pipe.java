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
    protected boolean closeStreamOnEOF;
    protected ErrorCallback errCB;
    
    public Pipe(InputStream in, OutputStream out)
    {
        this.in = in;
        this.out = out;
        setName("pipe");
    }
    
    public Pipe bufSize(int size)
    {
        bufSize = size;
        return this;
    }
    
    public Pipe closeOutputStreamOnEOF(boolean choice)
    {
        closeStreamOnEOF = choice;
        return this;
    }
    
    public Pipe daemon(boolean choice)
    {
        setDaemon(choice);
        return this;
    }
    
    public Pipe errorCallback(ErrorCallback cb)
    {
        errCB = cb;
        return this;
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
            if (closeStreamOnEOF)
                out.close();
        } catch (IOException ioe) {
            if (errCB != null)
                errCB.hadIOException(ioe);
        }
    }
    
}
