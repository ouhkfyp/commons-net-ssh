package org.apache.commons.net.ssh.connection;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;

import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Event;
import org.apache.commons.net.ssh.util.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PortForwardingDaemon
{
    
    private class DirectTCPIPChannel extends AbstractChannel
    {
        
        public static final String TYPE = "direct-tcpip";
        private final Socket sock;
        
        private DirectTCPIPChannel(Socket sock)
        {
            this.sock = sock;
        }
        
        public String getType()
        {
            return TYPE;
        }
        
        private void start() throws IOException
        {
            sock.setSendBufferSize(remoteWin.getMaxPacketSize());
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
        
        @Override
        protected Buffer buildOpenReq()
        {
            return super.buildOpenReq() //
                        .putString(host) //
                        .putInt(port) //
                        .putString(ss.getInetAddress().getHostAddress()) //
                        .putInt(ss.getLocalPort());
        }
        
    }
    
    private final ConnectionService conn;
    private final Event<ConnectionException> close =
            new Event<ConnectionException>("pfd close", ConnectionException.chainer);
    private final ServerSocket ss;
    private final String host;
    private final int port;
    private final Logger log = LoggerFactory.getLogger(getClass());
    
    private final Thread listener = new Thread()
        {
            {
                setName("pfd");
                setDaemon(true);
            }
            
            @Override
            public void run()
            {
                log.info("Listening on {}", ss.getLocalSocketAddress());
                while (!Thread.currentThread().isInterrupted()) {
                    Socket sock;
                    try {
                        sock = ss.accept();
                        log.info("Got connection from {}", sock.getRemoteSocketAddress());
                    } catch (IOException e) {
                        if (!Thread.currentThread().isInterrupted())
                            close.error(e);
                        break;
                    }
                    try {
                        DirectTCPIPChannel pfc = new DirectTCPIPChannel(sock);
                        conn.initAndAdd(pfc);
                        pfc.open();
                        pfc.start();
                    } catch (IOException justLog) {
                        log.error("While initializing direct-tcpip channel from {}: {}", sock.getRemoteSocketAddress(),
                                  justLog.toString());
                    }
                }
                close.set();
            }
        };
    
    public PortForwardingDaemon(ConnectionService conn, SocketAddress listeningAddr, String toHost, int toPort)
            throws IOException
    {
        this.conn = conn;
        this.host = toHost;
        this.port = toPort;
        this.ss = new ServerSocket();
        ss.setReceiveBufferSize(conn.getMaxPacketSize());
        ss.bind(listeningAddr);
    }
    
    public void join() throws ConnectionException
    {
        close.await();
    }
    
    public void startListening()
    {
        listener.start();
    }
    
    public void stopListening()
    {
        listener.interrupt();
        try {
            ss.close(); // in case it is blocked on accept (as it will be...)
        } catch (IOException ignore) {
        }
    }
    
}
