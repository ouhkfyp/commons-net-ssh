package org.apache.commons.net.ssh;

import org.apache.commons.net.ssh.util.Buffer;

public interface Listener
{
    
    SSHConstants.Message interestedIn();
    
    void handle(Buffer buffer);
    
}
