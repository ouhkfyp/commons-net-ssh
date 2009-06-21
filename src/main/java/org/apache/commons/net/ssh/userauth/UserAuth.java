package org.apache.commons.net.ssh.userauth;

import org.apache.commons.net.ssh.SSHConstants;
import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.Session;
import org.apache.commons.net.ssh.util.Buffer;

public class UserAuth implements Service
{
    
    public static final String serviceName = "ssh-userauth";
    
    private final Session session;
    private final String nextServiceName;
    
    private String[] allowedMethods = {"publickey", "password"};
    private String banner;
    
    private Method method; // currently active method
    
    public UserAuth(Session session, String nextServiceName)
    {
        this.session = session;
        this.nextServiceName = nextServiceName;
    }
    
    @Override
    public String getName()
    {
        return serviceName;
    }
    
    @Override
    public void handle(SSHConstants.Message cmd, Buffer packet)
    {
        switch (cmd)
        {
            case SSH_MSG_USERAUTH_BANNER:
                banner = packet.getString();
                break;
            case SSH_MSG_USERAUTH_SUCCESS:
                
        }
    }
    
    public String getBanner()
    {
        return banner;
    }
    
    private void setMethod(Method method)
    {
        this.method = method;
    }
    
    public void authPassword(String username, char[] password)
    {
        
        request(username);
    }
    
    private void request(String username)
    {
        Buffer buffer = session.createBuffer(SSHConstants.Message.SSH_MSG_USERAUTH_REQUEST);
        buffer.putString(username);
        buffer.putString(nextServiceName);
        
    }
    
}
