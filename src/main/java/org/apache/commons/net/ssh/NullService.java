package org.apache.commons.net.ssh;

import org.apache.commons.net.ssh.transport.Transport;
import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Constants.Message;

public class NullService extends AbstractService
{
    
    public NullService(Transport trans)
    {
        super("null-service", trans);
    }
    
    public void handle(Message msg, Buffer buffer) throws TransportException
    {
        throw new TransportException("NullService can't handle packet " + msg);
    }
    
    public void notifyError(SSHException ex)
    {
    }
    
}
