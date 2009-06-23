package org.apache.commons.net.ssh;

import java.io.IOException;
import java.net.Socket;

import org.apache.commons.net.ssh.util.Buffer;

public interface Session
{
    
    /**
     * Create a new buffer for the specified SSH packet and reserve the needed space (5 bytes) for the packet header.
     * 
     * @param cmd
     *            the SSH command
     * @return a new buffer ready for write
     */
    Buffer createBuffer(Constants.Message cmd);

    /**
     * Send a disconnect packet with the given reason and message, and close the session.
     * 
     * @param reason
     *            the reason code for this disconnect
     * @param msg
     *            the text message
     * @throws IOException
     *             if an error occured sending the packet
     */
    void disconnect(int reason, String msg) throws IOException;
    
    String getClientVersion();
    
    /**
     * Retrieve the factory manager
     * 
     * @return the factory manager for this session
     */
    FactoryManager getFactoryManager();
    
    String getServerVersion();
    
    void init(Socket socket) throws Exception;
    
    boolean isRunning();
    
    void setAuthenticated(boolean authed);
    
    void setHostKeyVerifier(HostKeyVerifier hkv);
    
    void startService(Service service) throws Exception;
    
    /**
     * Encode the payload as an SSH packet and send it over the session.
     * 
     * @param payload
     * @throws IOException
     */    
    int writePacket(Buffer payload) throws IOException;
    
}
