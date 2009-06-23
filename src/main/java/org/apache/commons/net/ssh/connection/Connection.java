package org.apache.commons.net.ssh.connection;

import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.Constants;
import org.apache.commons.net.ssh.Session;
import org.apache.commons.net.ssh.util.Buffer;

public class Connection implements Service
{

    private static final String SERVICE_NAME = "ssh-connection";
    private final Session session;
    
    public Connection(Session session)
    {
        this.session = session;
    }
    
    public String getName()
    {
        return SERVICE_NAME;
    }

    public void handle(Constants.Message cmd, Buffer packet)
    {
        // TODO for July
    }
    
}
