package org.apache.commons.net.ssh.connection;

import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Constants;

public class SessionChannel extends AbstractChannel implements Session, Session.Command, Session.Shell,
        Session.Subsystem
{
    
    private Integer exitStatus;
    private Signal exitSignal;
    private Boolean flowControl;
    private ChannelInputStream err;
    
    protected SessionChannel()
    {
        super(NAME);
    }
    
    public void allocateDefaultPTY() throws ConnectionException, TransportException
    {
        Map<TerminalMode, Integer> modes = new HashMap<TerminalMode, Integer>();
        modes.put(TerminalMode.ISIG, 1);
        modes.put(TerminalMode.ICANON, 1);
        modes.put(TerminalMode.ECHO, 1);
        modes.put(TerminalMode.ECHOE, 1);
        modes.put(TerminalMode.ECHOK, 1);
        modes.put(TerminalMode.ECHONL, 0);
        modes.put(TerminalMode.NOFLSH, 0);
        allocatePTY("dummy", 80, 40, 640, 480, modes);
    }
    
    public void allocatePTY(String term, int cols, int rows, int width, int height, Map<TerminalMode, Integer> modes)
            throws ConnectionException, TransportException
    {
        chanReq("pty-req", //
                true, // 
                new Buffer().putString(term) //
                            .putInt(cols) //
                            .putInt(rows) //
                            .putInt(width) //
                            .putInt(height) //
                            .putBytes(TerminalMode.encode(modes)) //
        ).await(); // wait for reply
    }
    
    public Boolean canDoFlowControl()
    {
        return flowControl;
    }
    
    public void changeWindowDimensions(int cols, int rows, int width, int height) throws TransportException
    {
        chanReq("pty-req", //
                false, //
                new Buffer().putInt(cols) //
                            .putInt(rows) //
                            .putInt(width) //
                            .putInt(height));
    }
    
    public Command exec(String command) throws ConnectionException, TransportException
    {
        chanReq("exec", true, new Buffer().putString(command)).await();
        return this;
    }
    
    public InputStream getErr()
    {
        return err;
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
        chanReq("env", true, new Buffer().putString(name).putString(value)).await();
    }
    
    public void signal(Signal sig) throws TransportException
    {
        chanReq("signal", false, new Buffer().putString(sig.getName()));
    }
    
    public Shell startShell() throws ConnectionException, TransportException
    {
        chanReq("shell", true, null).await();
        return this;
    }
    
    public Subsystem startSubsysytem(String name) throws ConnectionException, TransportException
    {
        chanReq("subsystem", true, new Buffer().putString(name)).await();
        return this;
    }
    
    @Override
    protected void handleExtendedData(int dataTypeCode, Buffer buf) throws ConnectionException, TransportException
    {
        if (dataTypeCode == 1) {
            
        } else
            trans.writePacket(new Buffer(Constants.Message.CHANNEL_FAILURE).putInt(recipient));
    }
    
}
