package org.apache.commons.net.ssh.transport;

import org.apache.commons.net.ssh.SSHException;
import org.apache.commons.net.ssh.Constants.DisconnectReason;

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
        // TODO Auto-generated constructor stub
    }
    
    public TransportException(DisconnectReason code)
    {
        super(code);
        // TODO Auto-generated constructor stub
    }
    
    public TransportException(DisconnectReason code, String message)
    {
        super(code, message);
        // TODO Auto-generated constructor stub
    }
    
    public TransportException(DisconnectReason code, String message, Throwable cause)
    {
        super(code, message, cause);
        // TODO Auto-generated constructor stub
    }
    
    public TransportException(DisconnectReason code, Throwable cause)
    {
        super(code, cause);
        // TODO Auto-generated constructor stub
    }
    
    public TransportException(String message)
    {
        super(message);
        // TODO Auto-generated constructor stub
    }
    
    public TransportException(String message, Throwable cause)
    {
        super(message, cause);
        // TODO Auto-generated constructor stub
    }
    
    public TransportException(Throwable cause)
    {
        super(cause);
        // TODO Auto-generated constructor stub
    }
    
}
