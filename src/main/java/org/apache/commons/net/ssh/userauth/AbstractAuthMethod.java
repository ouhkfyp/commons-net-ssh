package org.apache.commons.net.ssh.userauth;

import java.io.IOException;

import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.transport.Session;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractAuthMethod implements AuthMethod
{
    protected final Logger log = LoggerFactory.getLogger(getClass());
    
    protected final Session session;
    protected final Service nextService;
    protected final String username;
    protected String[] allowed;
    
    public AbstractAuthMethod(Session session, Service nextService, String username)
    {
        this.session = session;
        this.nextService = nextService;
        this.username = username;
    }
    
    abstract protected Buffer buildRequest(Buffer buf);
    
    public String[] getAllowedMethods()
    {
        return allowed;
    }
    
    public Service getNextService()
    {
        return nextService;
    }
    
    public String getUsername()
    {
        return username;
    }
    
    public void request() throws IOException
    {
        Buffer buf = session.createBuffer(Constants.Message.SSH_MSG_USERAUTH_REQUEST);
        buf.putString(username);
        buf.putString(nextService.getName());
        buf.putString(getName());
        session.writePacket(buildRequest(buf));
    }
    
}
