package org.apache.commons.net.ssh.connection;

import org.apache.commons.net.ssh.transport.TransportException;

public interface ConnectionService
{
    
    String NAME = "ssh-connection";
    
    int getMaxPacketSize();
    
    void initAndAdd(Channel chan);
    
    Session startSession() throws ConnectionException, TransportException;
    
}
