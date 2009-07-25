package org.apache.commons.net.ssh.connection;

import java.io.InputStream;
import java.io.OutputStream;

import org.apache.commons.net.ssh.SSHException;
import org.apache.commons.net.ssh.transport.Transport;
import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Constants;

public interface Channel
{
    
    void close() throws TransportException, ConnectionException;
    
    int getID();
    
    InputStream getInputStream();
    
    int getLocalMaxPacketSize();
    
    int getLocalWinSize();
    
    OutputStream getOutputStream();
    
    int getRecipient();
    
    int getRemoteMaxPacketSize();
    
    int getRemoteWinSize();
    
    Transport getTransport();
    
    String getType();
    
    void handle(Constants.Message cmd, Buffer buf) throws ConnectionException, TransportException;
    
    void init(int recipient, int remoteWinSize, int remoteMaxPacketSize);
    
    boolean isOpen();
    
    void notifyError(SSHException exception);
    
    void open() throws ConnectionException, TransportException;
    
    void sendEOF() throws TransportException;
    
}
