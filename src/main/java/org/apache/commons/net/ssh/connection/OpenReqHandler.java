package org.apache.commons.net.ssh.connection;

import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.util.Buffer;

public interface OpenReqHandler
{
    
    String getSupportedChannelType();
    
    void handleOpenReq(Buffer buf) throws ConnectionException, TransportException;
    
}
