package org.apache.commons.net.ssh;

import org.apache.commons.net.ssh.util.Buffer;

public interface Service
{
    
    String getName();
    
    void handle(SSHConstants.Message cmd, Buffer packet);
    
}
