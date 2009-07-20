package org.apache.commons.net.ssh.connection;

import org.apache.commons.net.ssh.SSHException;
import org.apache.commons.net.ssh.transport.Transport;
import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Constants;

public interface Channel extends IO
{
    
    void close() throws TransportException, ConnectionException;
    
    int getID();
    
    int getRecipient();
    
    Transport getTransport();
    
    String getType();
    
    boolean handle(Constants.Message cmd, Buffer buf) throws ConnectionException, TransportException;
    
    boolean isOpen();
    
    void notifyError(SSHException exception);
    
    void open() throws ConnectionException, TransportException;
    
    void sendEOF() throws TransportException;
    
}
