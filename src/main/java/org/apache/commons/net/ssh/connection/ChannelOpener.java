package org.apache.commons.net.ssh.connection;

import org.apache.commons.net.ssh.util.Buffer;

public interface ChannelOpener
{
    
    Channel handleReq(ConnectionService conn, Buffer buf);
    
}
