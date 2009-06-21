package org.apache.commons.net.ssh;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

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
    public abstract Buffer createBuffer(SSHConstants.Message cmd);

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
    public abstract void disconnect(int reason, String msg) throws IOException;
    
    public abstract String getClientVersion();
    
    /**
     * Retrieve the factory manager
     * 
     * @return the factory manager for this session
     */
    public abstract FactoryManager getFactoryManager();
    
    public abstract String getServerVersion();
    
    public abstract void init(InputStream input, OutputStream output) throws Exception;
    
    public abstract boolean isRunning();
    
    public abstract void startService(Service service) throws Exception;
    
    /**
     * Encode the payload as an SSH packet and send it over the session.
     * 
     * @param payload
     * @throws IOException
     */    
    public abstract int writePacket(Buffer payload) throws IOException;
    
    public abstract void setAuthenticated(boolean authed);
    
}
