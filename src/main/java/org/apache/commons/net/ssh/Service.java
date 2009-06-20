package org.apache.commons.net.ssh;

import org.apache.commons.net.ssh.SSHConstants.Message;
import org.apache.commons.net.ssh.util.Buffer;

public interface Service
{
 
    void init(Session session);
    
    String getName();
    
    void handle(Message cmd, Buffer packet);
    
}
