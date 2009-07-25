package org.apache.commons.net.ssh.connection;

import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Constants.Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractOpenReqHandler implements OpenReqHandler
{
    
    protected class OpenReq
    {
        final int recipient;
        final int winSize;
        final int maxPacketSize;
        
        OpenReq(Buffer buf)
        {
            recipient = buf.getInt();
            winSize = buf.getInt();
            maxPacketSize = buf.getInt();
        }
        
        void confirm(Channel chan) throws TransportException
        {
            log.debug("Confirming `{}` channel #{}", chan.getType(), chan.getID());
            chan.init(recipient, winSize, maxPacketSize);
            conn.getTransport()
                .writePacket(new Buffer(Message.CHANNEL_OPEN_CONFIRMATION) //
                                                                          .putInt(recipient) //
                                                                          .putInt(chan.getID()) //
                                                                          .putInt(conn.getWindowSize()) //
                                                                          .putInt(conn.getMaxPacketSize()));
        }
        
        void reject(int reasonCode, String message) throws TransportException
        {
            conn.getTransport().writePacket(new Buffer(Message.CHANNEL_OPEN_FAILURE) //
                                                                                    .putInt(reasonCode) //
                                                                                    .putString(message));
            
        }
        
    }
    
    protected final Logger log = LoggerFactory.getLogger(getClass());
    
    protected final ConnectionService conn;
    
    public AbstractOpenReqHandler(ConnectionService conn)
    {
        this.conn = conn;
        conn.attach(this);
    }
    
}
