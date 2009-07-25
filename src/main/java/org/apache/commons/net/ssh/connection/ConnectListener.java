/**
 * 
 */
package org.apache.commons.net.ssh.connection;

import java.io.IOException;
import java.net.Socket;
import java.net.SocketAddress;

import org.apache.commons.net.ssh.util.Pipe;
import org.apache.commons.net.ssh.util.Pipe.ErrorCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public interface ConnectListener
{
    
    class SocketForwardingConnectListener implements ConnectListener
    {
        
        protected final SocketAddress addr;
        protected final Logger log = LoggerFactory.getLogger(getClass());
        
        public SocketForwardingConnectListener(SocketAddress addr)
        {
            this.addr = addr;
        }
        
        public void gotConnect(Channel.Forwarded chan) throws IOException
        {
            log.info("New connection from " + chan.getOriginatorIP() + ":" + chan.getOriginatorPort());
            
            Socket sock = new Socket();
            sock.connect(addr);
            
            ErrorCallback chanCloser = Pipe.closeOnErrorCallback(chan);
            
            // sock2chan
            new Pipe(sock.getInputStream(), chan.getOutputStream()) //
                                                                   .bufSize(chan.getRemoteMaxPacketSize()) //
                                                                   .closeOutputStreamOnEOF(true) //
                                                                   .errorCallback(chanCloser) //
                                                                   .daemon(true) //
                                                                   .start();
            
            // chan2sock
            new Pipe(chan.getInputStream(), sock.getOutputStream()) //
                                                                   .bufSize(chan.getLocalMaxPacketSize()) //                                                       
                                                                   .closeOutputStreamOnEOF(true) //
                                                                   .errorCallback(chanCloser) //
                                                                   .daemon(true) //
                                                                   .start();
        }
        
    }
    
    void gotConnect(Channel.Forwarded chan) throws IOException;
    
}