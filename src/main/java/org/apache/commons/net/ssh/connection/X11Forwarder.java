package org.apache.commons.net.ssh.connection;

import java.io.IOException;

import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.util.Buffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class X11Forwarder implements ForwardedChannelOpener
{
    
    public static class X11Channel extends AbstractForwardedChannel
    {
        public static final String TYPE = "x11";
        
        protected X11Channel(ConnectionService conn, Buffer buf)
        {
            super(conn, buf);
            this.origIP = buf.getString();
            this.origPort = buf.getInt();
        }
        
        public String getType()
        {
            return TYPE;
        }
    }
    
    protected final Logger log = LoggerFactory.getLogger(getClass());
    
    protected final ConnectionService conn;
    protected final ConnectListener listener;
    
    public X11Forwarder(ConnectionService conn, ConnectListener listener)
    {
        this.conn = conn;
        this.listener = listener;
        conn.attach(this);
    }
    
    public String getChannelType()
    {
        return X11Channel.TYPE;
    }
    
    public void handleOpen(Buffer buf) throws ConnectionException, TransportException
    {
        X11Channel chan = new X11Channel(conn, buf);
        chan.confirm();
        try {
            listener.gotConnect(chan);
        } catch (IOException ioe) {
            chan.close();
        }
    }
    
}
