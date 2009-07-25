package org.apache.commons.net.ssh.userauth;

import org.apache.commons.net.ssh.transport.Transport;

public interface AuthParams
{
    
    String getNextServiceName();
    
    Transport getTransport();
    
    String getUsername();
    
}
