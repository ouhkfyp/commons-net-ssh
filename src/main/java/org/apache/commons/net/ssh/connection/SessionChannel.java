package org.apache.commons.net.ssh.connection;

import java.io.InputStream;
import java.io.OutputStream;

import org.apache.commons.net.ssh.util.Buffer;

public class SessionChannel extends AbstractChannel implements Session, Session.Command, Session.Shell,
        Session.Subsystem
{
    
    private int exitStatus;
    private Signal exitSignal;
    
    protected SessionChannel()
    {
        super(NAME);
    }
    
    public void allocatePTY(String term, int widthChars, int heightChars, int widthPixels, int heightPixels)
    {
        // TODO Auto-generated method stub
        
    }
    
    public Command exec(String command)
    {
        // TODO Auto-generated method stub
        return null;
    }
    
    public Signal getExitSignal()
    {
        return exitSignal;
    }
    
    public int getExitStatus()
    {
        return exitStatus;
    }
    
    public InputStream getInputStream()
    {
        // TODO Auto-generated method stub
        return null;
    }
    
    public OutputStream getOutputStream()
    {
        // TODO Auto-generated method stub
        return null;
    }
    
    public void handleEOF(Buffer buf)
    {
        // TODO Auto-generated method stub
        
    }
    
    public void handleFailure(Buffer buf)
    {
        // TODO Auto-generated method stub
        
    }
    
    public void handleRequest(Buffer buffer)
    {
        log.info("Received SSH_MSG_CHANNEL_REQUEST on channel {}", id);
        String req = buffer.getString();
        if ("exit-status".equals(req)) {
            buffer.getBoolean();
            //synchronized (lock) {
            exitStatus = Integer.valueOf(buffer.getInt());
            //lock.notifyAll();
            //}
        } else if ("exit-signal".equals(req)) {
            buffer.getBoolean();
            //synchronized (lock) {
            exitSignal = Signal.fromString(buffer.getString());
            //lock.notifyAll();
            //}
        }
        // TODO: handle other channel requests
    }
    
    public void setEnvVar(String name, String value)
    {
        // TODO Auto-generated method stub
        
    }
    
    public void signal(Signal sig)
    {
        // TODO Auto-generated method stub
        
    }
    
    public Shell startShell()
    {
        // TODO Auto-generated method stub
        return null;
    }
    
    public Subsystem startSubsysytem(String name)
    {
        // TODO Auto-generated method stub
        return null;
    }
    
}
