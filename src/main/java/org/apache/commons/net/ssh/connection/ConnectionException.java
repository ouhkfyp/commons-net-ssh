package org.apache.commons.net.ssh.connection;

import org.apache.commons.net.ssh.SSHException;
import org.apache.commons.net.ssh.util.FriendlyChainer;
import org.apache.commons.net.ssh.util.Constants.DisconnectReason;

public class ConnectionException extends SSHException
{
    
    public static final FriendlyChainer<ConnectionException> chainer = new FriendlyChainer<ConnectionException>()
        {
            public ConnectionException chain(Throwable t)
            {
                if (t instanceof ConnectionException)
                    return (ConnectionException) t;
                else
                    return new ConnectionException(t);
            }
        };
    
    public ConnectionException()
    {
        super();
    }
    
    public ConnectionException(DisconnectReason code)
    {
        super(code);
    }
    
    public ConnectionException(DisconnectReason code, String message)
    {
        super(code, message);
    }
    
    public ConnectionException(DisconnectReason code, String message, Throwable cause)
    {
        super(code, message, cause);
    }
    
    public ConnectionException(DisconnectReason code, Throwable cause)
    {
        super(code, cause);
    }
    
    public ConnectionException(String message)
    {
        super(message);
    }
    
    public ConnectionException(String message, Throwable cause)
    {
        super(message, cause);
    }
    
    public ConnectionException(Throwable cause)
    {
        super(cause);
    }
    
}
