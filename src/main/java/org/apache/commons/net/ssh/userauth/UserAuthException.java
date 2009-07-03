package org.apache.commons.net.ssh.userauth;

import org.apache.commons.net.ssh.SSHException;
import org.apache.commons.net.ssh.Constants.DisconnectReason;

public class UserAuthException extends SSHException
{
    
    public static UserAuthException chain(Exception e)
    {
        if (e instanceof UserAuthException)
            return (UserAuthException) e;
        else
            return new UserAuthException(e);
    }
    
    public UserAuthException()
    {
        super();
        // TODO Auto-generated constructor stub
    }
    
    public UserAuthException(DisconnectReason code)
    {
        super(code);
        // TODO Auto-generated constructor stub
    }
    
    public UserAuthException(DisconnectReason code, String message)
    {
        super(code, message);
        // TODO Auto-generated constructor stub
    }
    
    public UserAuthException(DisconnectReason code, String message, Throwable cause)
    {
        super(code, message, cause);
        // TODO Auto-generated constructor stub
    }
    
    public UserAuthException(DisconnectReason code, Throwable cause)
    {
        super(code, cause);
        // TODO Auto-generated constructor stub
    }
    
    public UserAuthException(String message)
    {
        super(message);
        // TODO Auto-generated constructor stub
    }
    
    public UserAuthException(String message, Throwable cause)
    {
        super(message, cause);
        // TODO Auto-generated constructor stub
    }
    
    public UserAuthException(Throwable cause)
    {
        super(cause);
        // TODO Auto-generated constructor stub
    }
    
}
