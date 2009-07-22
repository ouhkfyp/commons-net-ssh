package org.apache.commons.net.ssh.connection;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.IOUtils;

public class RemoteForwardingHandler implements ChannelOpener
{
    
    private class ForwardedTCPIPChannel extends AbstractChannel
    {
        
        public static final String TYPE = "forwarded-tcpip";
        private final Socket sock;
        
        private final String host;
        private final int port;
        private final String origIP;
        private final int origPort;
        
        private ForwardedTCPIPChannel(Buffer buf) throws IOException
        {
            recipient = buf.getInt();
            remoteWin.init(buf.getInt(), buf.getInt());
            host = buf.getString();
            port = buf.getInt();
            origIP = buf.getString();
            origPort = buf.getInt();
            sock = new Socket();
            sock.connect(new InetSocketAddress(host, port));
            open.set();
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
        
        private void startForwarding() throws IOException
        {
            sock.setSendBufferSize(localWin.getMaxPacketSize());
            IOUtils.ErrorCallback cb = new IOUtils.ErrorCallback()
                {
                    public void onIOException(IOException e)
                    {
                        sendClose();
                    }
                };
            IOUtils.pipe(in, sock.getOutputStream(), localWin.getMaxPacketSize(), cb);
            IOUtils.pipe(sock.getInputStream(), out, remoteWin.getMaxPacketSize(), cb);
        }
        
    }
    
    public Channel handleReq(ConnectionService conn, Buffer buf)
    {
        return null;
    }
    
}
