package org.apache.commons.net.ssh;

import org.apache.commons.net.ssh.util.Constants.DisconnectReason;

public class TransportException extends SSHException
{
    
    public static TransportException chain(Exception e)
    {
        if (e instanceof TransportException)
            return (TransportException) e;
        else
            return new TransportException(e);
    }
    
    public TransportException()
    {
        super();
    }
    
    public TransportException(DisconnectReason code)
    {
        super(code);
    }
    
    public TransportException(DisconnectReason code, String message)
    {
        super(code, message);
    }
    
    public TransportException(DisconnectReason code, String message, Throwable cause)
    {
        super(code, message, cause);
    }
    
    public TransportException(DisconnectReason code, Throwable cause)
    {
        super(code, cause);
    }
    
    public TransportException(String message)
    {
        super(message);
    }
    
    public TransportException(String message, Throwable cause)
    {
        super(message, cause);
    }
    
    public TransportException(Throwable cause)
    {
        super(cause);
    }
    
}
