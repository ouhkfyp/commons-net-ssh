package org.apache.commons.net.ssh.connection;

import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.util.Buffer;

public interface ForwardedChannelOpener
{
    
    String getChannelType();
    
    void handleOpen(Buffer buf) throws ConnectionException, TransportException;
    
}
