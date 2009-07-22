package org.apache.commons.net.ssh.connection;

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Constants.Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RemotePortForwarding implements OpenReqHandler
{
    
    public interface ConnectListener
    {
        void connected(ForwardedTCPIPChannel chan);
    }
    
    public class ForwardedTCPIPChannel extends AbstractChannel
    {
        
        private static final String TYPE = "forwarded-tcpip";
        
        private final String host;
        private final int port;
        private final String origIP;
        private final int origPort;
        
        private ForwardedTCPIPChannel(ConnectionService conn, Buffer buf) throws TransportException
        {
            super(conn);
            init(buf.getInt(), buf.getInt(), buf.getInt());
            host = buf.getString();
            port = buf.getInt();
            origIP = buf.getString();
            origPort = buf.getInt();
            if (listeners.containsKey(port)) {
                log.debug("Confirming forwarded-tcpip channel - local=#{}, remote=#{}", id, recipient);
                trans.writePacket(newBuffer(Message.CHANNEL_OPEN_CONFIRMATION) //
                                                                              .putInt(id) //
                                                                              .putInt(localWin.getSize()) //
                                                                              .putInt(localWin.getMaxPacketSize()));
                listeners.get(port).connected(this);
            } else {
                conn.forget(this);
                trans
                     .writePacket(new Buffer(Message.CHANNEL_OPEN_FAILURE) //
                                                                          .putInt(
                                                                                  OpenFailException.ADMINISTRATIVELY_PROHIBITED) //
                                                                          .putString(
                                                                                     "Forwarding was not requested on port " //  
                                                                                             + port));
            }
            
        }
        
        public String getConnectedAddr()
        {
            return host;
        }
        
        public int getConnectedPort()
        {
            return port;
        }
        
        public String getOriginatingIPAddress()
        {
            return origIP;
        }
        
        public int getOriginatingPort()
        {
            return origPort;
        }
        
        public String getType()
        {
            return TYPE;
        }
        
        @Override
        public void open()
        {
            // Disable
        }
        
    }
    
    public static final String PF_REQ = "tcpip-forward";
    
    protected final Logger log = LoggerFactory.getLogger(getClass());
    
    private final ConnectionService conn;
    private final Map<Integer, ConnectListener> listeners = new HashMap<Integer, ConnectListener>();
    
    public RemotePortForwarding(ConnectionService conn)
    {
        this.conn = conn;
        conn.attach(this);
    }
    
    public int bind(String addrToBind, int port, ConnectListener listener) throws ConnectionException,
            TransportException
    {
        Buffer reply = conn.sendGlobalRequest(PF_REQ, true, new Buffer() //
                                                                        .putString(addrToBind) //
                                                                        .putInt(port)) //
                           .get(conn.getTimeout());
        int p = port == 0 ? reply.getInt() : port;
        log.info("Remote end listening on `{}`:{}", addrToBind, p);
        listeners.put(p, listener);
        return p;
    }
    
    public String getSupportedChannelType()
    {
        return ForwardedTCPIPChannel.TYPE;
    }
    
    public void handleOpenReq(Buffer buf) throws TransportException
    {
        ForwardedTCPIPChannel chan = new ForwardedTCPIPChannel(conn, buf);
        listeners.get(chan.getConnectedPort());
    }
    
}
