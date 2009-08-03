package org.apache.commons.net.ssh;

import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Constants.Message;

public interface PacketHandler
{
    
    void handle(Message msg, Buffer buf) throws SSHException;
    
}
