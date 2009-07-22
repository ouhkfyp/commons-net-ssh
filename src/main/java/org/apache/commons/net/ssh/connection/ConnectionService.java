package org.apache.commons.net.ssh.connection;

import org.apache.commons.net.ssh.transport.Transport;
import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Future;

public interface ConnectionService
{
    
    String NAME = "ssh-connection";
    
    public Future<Buffer, ConnectionException> sendGlobalRequest(String name, boolean wantReply, Buffer specifics)
            throws TransportException;
    
    void attach(Channel chan);
    
    void attach(OpenReqHandler handler);
    
    void forget(Channel chan);
    
    void forget(OpenReqHandler handler);
    
    int getMaxPacketSize();
    
    int getTimeout();
    
    Transport getTransport();
    
    int getWindowSize();
    
    int nextID();
    
    void setMaxPacketSize(int maxPacketSize);
    
    void setTimeout(int timeout);
    
    void setWindowSize(int windowSize);
    
}
