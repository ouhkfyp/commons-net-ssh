package org.apache.commons.net.ssh.connection;

import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.util.Buffer;

public class SessionChannel extends AbstractChannel implements Session, Session.Command, Session.Shell,
        Session.Subsystem
{
    
    private Integer exitStatus;
    private Signal exitSignal;
    private Boolean flowControl;
    
    protected SessionChannel()
    {
        super(NAME);
    }
    
    public void allocatePTY(String term, int cols, int rows, int width, int height) throws ConnectionException,
            TransportException
    {
        request(makeReqBuf("pty-req", true) //                                     
                                           .putString(term) //
                                           .putInt(cols) //
                                           .putInt(rows) //
                                           .putInt(width) //
                                           .putInt(height));
    }
    
    public Boolean canControlFlow()
    {
        return flowControl;
    }
    
    public void changeWindowDimensions(int cols, int rows, int width, int height) throws TransportException
    {
        trans.writePacket(makeReqBuf("window-change", false) //
                                                            .putInt(cols) //
                                                            .putInt(rows) //
                                                            .putInt(width) //
                                                            .putInt(height));
    }
    
    public Command exec(String command) throws ConnectionException, TransportException
    {
        request(makeReqBuf("exec", true).putString(command));
        return this;
    }
    
    public Signal getExitSignal()
    {
        return exitSignal;
    }
    
    public Integer getExitStatus()
    {
        return exitStatus;
    }
    
    @Override
    public void handleRequest(String req, Buffer buf)
    {
        if ("xon-xoff".equals(req))
            flowControl = buf.getBoolean();
        else if ("exit-status".equals(req))
            exitStatus = buf.getInt();
        else if ("exit-signal".equals(req))
            exitSignal = Signal.fromString(buf.getString());
        else
            log.warn("Dropping {} request", req);
    }
    
    public void setEnvVar(String name, String value) throws ConnectionException, TransportException
    {
        request(makeReqBuf("env", true).putString(name).putString(value));
    }
    
    public void signal(Signal sig) throws TransportException
    {
        trans.writePacket(makeReqBuf("signal", false).putString(sig.getName()));
    }
    
    public Shell startShell() throws ConnectionException, TransportException
    {
        request(makeReqBuf("shell", true));
        return this;
    }
    
    public Subsystem startSubsysytem(String name) throws ConnectionException, TransportException
    {
        request(makeReqBuf("subsystem", true).putString(name));
        return this;
    }
    
}
