package org.apache.commons.net.ssh.connection;

import java.io.InputStream;
import java.io.OutputStream;

public interface Session
{
    
    interface Command
    {
        
        InputStream getErr();
        
        Signal getExitSignal();
        
        int getExitStatus();
        
        InputStream getIn();
        
        OutputStream getOut();
        
        void signal(Signal sig);
        
    }
    
    interface Shell
    {
        
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
        
        @Override
        public String toString()
        {
            return name;
        }
        
    }
    
    interface Subsystem
    {
        
        InputStream getIn();
        
        OutputStream getOut();
        
    }
    
    public static String NAME = "session";
    
    void allocatePTY(String term, int widthChars, int heightChars, int widthPixels, int heightPixels);
    
    Command exec(String command);
    
    InputStream getInputStream();
    
    OutputStream getOutputStream();
    
    void setEnvVar(String name, String value);
    
    Shell startShell();
    
    Subsystem startSubsysytem(String name);
    
}
