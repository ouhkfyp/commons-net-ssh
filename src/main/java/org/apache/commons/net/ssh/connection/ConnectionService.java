package org.apache.commons.net.ssh.connection;

import org.apache.commons.net.ssh.transport.TransportException;

public interface ConnectionService
{
    
    String NAME = "ssh-connection";
    
    Session startSession() throws ConnectionException, TransportException;
    
}
