package org.apache.commons.net.ssh.connection;

import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Constants.Message;

public abstract class AbstractForwardedChannel extends AbstractChannel implements Channel.Forwarded
{
    
    protected String origIP;
    protected int origPort;
    
    protected AbstractForwardedChannel(ConnectionService conn, Buffer buf)
    {
        super(conn);
        init(buf);
    }
    
    public void confirm() throws TransportException
    {
        log.info("Confirming `{}` channel #{}", getType(), id);
        trans.writePacket(newBuffer(Message.CHANNEL_OPEN_CONFIRMATION) //
                                                                      .putInt(id) //
                                                                      .putInt(lwin.getSize()) //
                                                                      .putInt(lwin.getMaxPacketSize()));
        open.set();
        conn.attach(this);
    }
    
    public String getOriginatorIP()
    {
        return origIP;
    }
    
    public int getOriginatorPort()
    {
        return origPort;
    }
    
    public void reject(int reasonCode, String message) throws TransportException
    {
        log.info("Rejecting `{}` channel: {}", getType(), message);
        trans.writePacket(new Buffer(Message.CHANNEL_OPEN_FAILURE) //
                                                                  .putInt(reasonCode) //
                                                                  .putString(message));
    }
    
}
