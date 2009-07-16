package org.apache.commons.net.ssh.transport;

import org.apache.commons.net.ssh.SSHException;
import org.apache.commons.net.ssh.util.FriendlyChainer;
import org.apache.commons.net.ssh.util.Constants.DisconnectReason;

public class TransportException extends SSHException
{
    
    public static final FriendlyChainer<TransportException> chainer = new FriendlyChainer<TransportException>()
        {
            public TransportException chain(Throwable t)
            {
                if (t instanceof TransportException)
                    return (TransportException) t;
                else
                    return new TransportException(t);
            }
        };
    
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
    
    public TransportException chain(Throwable t)
    {
        if (t instanceof TransportException)
            return (TransportException) t;
        else
            return new TransportException(t);
    }
    
}
