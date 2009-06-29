package org.apache.commons.net.ssh.userauth;

import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.transport.Session;
import org.apache.commons.net.ssh.util.Buffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractAuthMethod implements AuthMethod
{
    protected final Logger log = LoggerFactory.getLogger(getClass());
    
    protected final Session session;
    protected final Service nextService;
    protected final String username;
    protected Set<String> allowed;
    
    public AbstractAuthMethod(Session session, Service nextService, String username)
    {
        this.session = session;
        this.nextService = nextService;
        this.username = username;
    }
    
    abstract protected Buffer buildRequest();
    
    public Buffer buildRequestCommon(Buffer buf)
    {
        buf.putString(username);
        buf.putString(nextService.getName());
        buf.putString(getName());
        return buf;
    }
    
    public Set<String> getAllowedMethods()
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
        log.debug("Sending SSH_MSG_USERAUTH_REQUEST: method={}", getName());
        session.writePacket(buildRequest());
    }
    
    protected void setAllowedMethods(String commaDelimed)
    {
        allowed = new LinkedHashSet<String>(Arrays.asList(commaDelimed.split(",")));
    }
    
}
