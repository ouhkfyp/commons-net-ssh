package org.apache.commons.net.ssh.userauth;

import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.transport.Transport;

public final class AuthParams
{
    
    private final Transport trans;
    private final String username;
    private final Service nextService;
    
    public AuthParams(Transport trans, String username, Service nextService)
    {
        this.trans = trans;
        this.username = username;
        this.nextService = nextService;
    }
    
    public Service getNextService()
    {
        return nextService;
    }
    
    public Transport getTransport()
    {
        return trans;
    }
    
    public String getUsername()
    {
        return username;
    }
    
}
