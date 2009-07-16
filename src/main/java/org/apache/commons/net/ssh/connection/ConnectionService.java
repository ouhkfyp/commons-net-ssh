package org.apache.commons.net.ssh.connection;

import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.transport.TransportException;

public interface ConnectionService extends Service
{
    
    String NAME = "ssh-connection";
    
    Session newSession() throws ConnectionException, TransportException;
    
}
