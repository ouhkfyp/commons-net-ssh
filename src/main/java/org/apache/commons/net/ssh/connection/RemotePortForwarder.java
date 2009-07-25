package org.apache.commons.net.ssh.connection;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.util.Buffer;

public class RemotePortForwarder extends AbstractOpenReqHandler
{
    
    public interface ConnectListener
    {
        void gotConnect(ForwardedTCPIPChannel chan) throws IOException;
    }
    
    public static final class Forward
    {
        
        private final String address;
        private int port;
        
        public Forward(int port)
        {
            this("", port);
        }
        
        public Forward(String address)
        {
            this(address, 0);
        }
        
        public Forward(String address, int port)
        {
            this.address = address;
            this.port = port;
        }
        
        @Override
        public boolean equals(Object obj)
        {
            if (obj == null || getClass() != obj.getClass())
                return false;
            Forward other = (Forward) obj;
            return address.equals(other.address) && port == other.port;
        }
        
        public String getAddress()
        {
            return address;
        }
        
        public int getPort()
        {
            return port;
        }
        
        @Override
        public int hashCode()
        {
            return toString().hashCode();
        }
        
        @Override
        public String toString()
        {
            return address + ":" + port;
        }
        
    }
    
    public static class ForwardedTCPIPChannel extends AbstractChannel
    {
        
        public static final String TYPE = "forwarded-tcpip";
        
        private final Forward fwd;
        private final String origIP;
        private final int origPort;
        
        public ForwardedTCPIPChannel(ConnectionService conn, Forward fwd, String origIP, int origPort)
                throws TransportException
        {
            super(conn);
            this.fwd = fwd;
            this.origIP = origIP;
            this.origPort = origPort;
        }
        
        public String getOriginatingIP()
        {
            return origIP;
        }
        
        public int getOriginatingPort()
        {
            return origPort;
        }
        
        public Forward getParentForward()
        {
            return fwd;
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
    public static final String PF_CANCEL = "cancel-tcpip-forward";
    
    protected final Map<Forward, ConnectListener> listeners = new HashMap<Forward, ConnectListener>();
    
    public RemotePortForwarder(ConnectionService conn)
    {
        super(conn);
    }
    
    public Forward bind(Forward forward, ConnectListener listener) throws ConnectionException, TransportException
    {
        Buffer reply = conn.sendGlobalRequest(PF_REQ, true, new Buffer() //
                                                                        .putString(forward.address) //
                                                                        .putInt(forward.port)) //
                           .get(conn.getTimeout());
        if (forward.port == 0)
            forward.port = reply.getInt();
        log.info("Remote end listening on {}", forward);
        listeners.put(forward, listener);
        return forward;
    }
    
    public void cancel(Forward fwd) throws TransportException, ConnectionException
    {
        try {
            conn.sendGlobalRequest(PF_CANCEL, true, new Buffer() //
                                                                .putString(fwd.address) //
                                                                .putInt(fwd.port)) //
                .get(conn.getTimeout());
        } finally {
            listeners.remove(fwd);
            if (listeners.isEmpty())
                conn.forget(this);
        }
    }
    
    public Set<Forward> getActiveForwards()
    {
        return listeners.keySet();
    }
    
    public String getSupportedChannelType()
    {
        return ForwardedTCPIPChannel.TYPE;
    }
    
    public void handleOpenReq(Buffer buf) throws ConnectionException, TransportException
    {
        OpenReq or = new OpenReq(buf);
        Forward fwd = new Forward(buf.getString(), buf.getInt());
        if (listeners.containsKey(fwd)) {
            ForwardedTCPIPChannel chan = new ForwardedTCPIPChannel(conn, fwd, buf.getString(), buf.getInt());
            or.confirm(chan);
            try {
                listeners.get(fwd).gotConnect(chan);
            } catch (IOException logged) {
                log.warn("Error in ConnectListener callback: {}", logged.toString());
                chan.close();
            }
        } else
            or.reject(OpenFailException.ADMINISTRATIVELY_PROHIBITED, "Forwarding was not requested on [" + fwd + "]");
    }
    
}
