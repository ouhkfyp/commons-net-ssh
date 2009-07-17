package org.apache.commons.net.ssh.userauth;

import org.apache.commons.net.ssh.SSHException;
import org.apache.commons.net.ssh.util.FriendlyChainer;
import org.apache.commons.net.ssh.util.Constants.DisconnectReason;

public class UserAuthException extends SSHException
{
    
    public static final FriendlyChainer<UserAuthException> chainer = new FriendlyChainer<UserAuthException>()
        {
            
            public UserAuthException chain(Throwable t)
            {
                if (t instanceof UserAuthException)
                    return (UserAuthException) t;
                else
                    return new UserAuthException(t);
            }
            
        };
    
    public UserAuthException()
    {
        super();
    }
    
    public UserAuthException(DisconnectReason code)
    {
        super(code);
    }
    
    public UserAuthException(DisconnectReason code, String message)
    {
        super(code, message);
    }
    
    public UserAuthException(DisconnectReason code, String message, Throwable cause)
    {
        super(code, message, cause);
    }
    
    public UserAuthException(DisconnectReason code, Throwable cause)
    {
        super(code, cause);
    }
    
    public UserAuthException(String message)
    {
        super(message);
    }
    
    public UserAuthException(String message, Throwable cause)
    {
        super(message, cause);
    }
    
    public UserAuthException(Throwable cause)
    {
        super(cause);
    }
    
}
