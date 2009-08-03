package org.apache.commons.net.ssh.transport;

import org.apache.commons.net.ssh.util.Buffer;

public interface PacketWriter
{
    
    long writePacket(Buffer packet) throws TransportException;
    
}
