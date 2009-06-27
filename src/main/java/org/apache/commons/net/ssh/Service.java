package org.apache.commons.net.ssh;

import java.io.IOException;

import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Constants;

public interface Service
{
    /**
     * Get the assignmed name for this SSH service.
     * 
     * @return service name
     */
    String getName();
    
    /**
     * Once a service has been successfully requested, SSH packets not recognized by the transport
     * layer are passed to the service instance for handling.
     * 
     * @param cmd
     * @param packet
     * @throws IOException
     */
    void handle(Constants.Message cmd, Buffer packet) throws IOException;
    
    void request() throws IOException;
    
    /**
     * Notify the service that an error occured in the transport layer.
     * 
     * @param ex
     */
    void setError(Exception ex);
    
}
