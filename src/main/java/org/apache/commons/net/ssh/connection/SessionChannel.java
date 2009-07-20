package org.apache.commons.net.ssh.connection;

import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.net.ssh.transport.Transport;
import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.IOUtils;
import org.apache.commons.net.ssh.util.Constants.DisconnectReason;

public class SessionChannel extends AbstractChannel implements Session, Session.Command, Session.Shell,
        Session.Subsystem
{
    
    private Integer exitStatus;
    
    private Signal exitSignal;
    private Boolean flowControl;
    private final ChannelInputStream err = new ChannelInputStream(localWin);
    
    public static final String TYPE = "session";
    
    SessionChannel(Transport trans, int id, int localWinSize, int localMaxPacketSize)
    {
        super(trans, id, localWinSize, localMaxPacketSize);
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
        sendChannelRequest("pty-req", //
                           true, // 
                           new Buffer().putString(term) //
                                       .putInt(cols) //
                                       .putInt(rows) //
                                       .putInt(width) //
                                       .putInt(height) //
                                       .putBytes(TerminalMode.encode(modes)) //
        ).get(); // wait for reply
    }
    
    public Buffer buildOpenRequest()
    {
        // TODO Auto-generated method stub
        return null;
    }
    
    public Boolean canDoFlowControl()
    {
        return flowControl;
    }
    
    public void changeWindowDimensions(int cols, int rows, int width, int height) throws TransportException
    {
        sendChannelRequest("pty-req", //
                           false, //
                           new Buffer().putInt(cols) //
                                       .putInt(rows) //
                                       .putInt(width) //
                                       .putInt(height));
    }
    
    public Command exec(String command) throws ConnectionException, TransportException
    {
        sendChannelRequest("exec", true, new Buffer().putString(command)).await(TIMEOUT);
        return this;
    }
    
    public InputStream getErrorStream()
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
    
    public String getType()
    {
        return TYPE;
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
        sendChannelRequest("env", true, new Buffer().putString(name).putString(value)).await(TIMEOUT);
    }
    
    public void signal(Signal sig) throws TransportException
    {
        sendChannelRequest("signal", false, new Buffer().putString(sig.getName()));
    }
    
    public Shell startShell() throws ConnectionException, TransportException
    {
        sendChannelRequest("shell", true, null).get();
        return this;
    }
    
    public Subsystem startSubsysytem(String name) throws ConnectionException, TransportException
    {
        sendChannelRequest("subsystem", true, new Buffer().putString(name)).get();
        return this;
    }
    
    @Override
    protected void closeStreams()
    {
        super.closeStreams();
        IOUtils.closeQuietly(err);
    }
    
    @Override
    protected void eofInputStreams()
    {
        super.eofInputStreams();
        err.eof();
    }
    
    @Override
    protected void handleExtendedData(int dataTypeCode, Buffer buf) throws ConnectionException, TransportException
    {
        if (dataTypeCode == 1)
            doWrite(buf, err);
        else
            throw new ConnectionException(DisconnectReason.PROTOCOL_ERROR);
    }
    
}
