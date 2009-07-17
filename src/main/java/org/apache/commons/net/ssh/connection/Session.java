package org.apache.commons.net.ssh.connection;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;

import org.apache.commons.net.ssh.transport.TransportException;

public interface Session
{
    
    interface Command
    {
        
        Boolean canDoFlowControl();
        
        InputStream getErr();
        
        Signal getExitSignal();
        
        Integer getExitStatus();
        
        InputStream getIn();
        
        OutputStream getOut();
        
        void signal(Signal sig) throws TransportException;
        
    }
    
    interface Shell
    {
        
        Boolean canDoFlowControl();
        
        InputStream getErr();
        
        InputStream getIn();
        
        OutputStream getOut();
        
    }
    
    enum Signal
    {
        
        SIG_ABRT("ABRT"),
        SIG_ALRM("ALRM"),
        SIG_FPE("FPE"),
        SIG_HUP("HUP"),
        SIG_ILL("ILL"),
        SIG_INT("INT"),
        SIG_KILL("KILL"),
        SIG_PIPE("PIPE"),
        SIG_QUIT("QUIT"),
        SIG_SEGV("SEGV"),
        SIG_TERM("TERM"),
        SIG_USR1("USR1"),
        SIG_USR2("USR2"),
        UNKNOWN("");
        
        public static Signal fromString(String name)
        {
            for (Signal sig : Signal.values())
                if (sig.name.equals(name))
                    return sig;
            Signal unknown = UNKNOWN;
            unknown.name = name;
            return unknown;
        }
        
        private String name;
        
        private Signal(String name)
        {
            this.name = name;
        }
        
        public String getName()
        {
            return name;
        }
        
    }
    
    interface Subsystem
    {
        
        Boolean canDoFlowControl();
        
        InputStream getIn();
        
        OutputStream getOut();
        
    }
    
    String NAME = "session";
    
    void allocateDefaultPTY() throws ConnectionException, TransportException;
    
    void allocatePTY(String term, int cols, int rows, int width, int height, Map<TerminalMode, Integer> modes)
            throws ConnectionException, TransportException;
    
    void changeWindowDimensions(int cols, int rows, int width, int height) throws TransportException;
    
    Command exec(String command) throws ConnectionException, TransportException;
    
    void setEnvVar(String name, String value) throws ConnectionException, TransportException;
    
    Shell startShell() throws ConnectionException, TransportException;
    
    Subsystem startSubsysytem(String name) throws ConnectionException, TransportException;
    
}
