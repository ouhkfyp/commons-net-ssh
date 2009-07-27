package examples.ssh;

import java.io.IOException;
import java.io.OutputStream;

import org.apache.commons.net.ssh.SSHClient;
import org.apache.commons.net.ssh.connection.Channel;
import org.apache.commons.net.ssh.connection.Session;
import org.apache.commons.net.ssh.connection.Session.Shell;
import org.apache.commons.net.ssh.util.Pipe;

class RudimentaryPTY
{
    
    //    static {
    //        BasicConfigurator.configure(new ConsoleAppender(new PatternLayout("[%t] %p %c{2} %m%n")));
    //    }
    
    public static void main(String... args) throws IOException
    {
        SSHClient client = new SSHClient();
        client.initUserKnownHosts();
        client.connect("localhost");
        Session session = null;
        try {
            
            client.authPublickey(System.getProperty("user.name"));
            
            session = client.startSession();
            session.allocateDefaultPTY();
            Shell shell = session.startShell();
            
            new Pipe("stdout", shell.getInputStream(), System.out) //
                                                                  .bufSize(((Channel) session).getLocalMaxPacketSize()) //
                                                                  .daemon(true) //
                                                                  .start();
            
            new Pipe("stderr", shell.getErrorStream(), System.err) //
                                                                  .bufSize(((Channel) session).getLocalMaxPacketSize()) //
                                                                  .daemon(true) //
                                                                  .start();
            
            // Now make System.in act as stdin. To exit, hit Ctrl+D.
            
            // This is kinda messy because java only allows console input after you hit return
            // But this is just an example... a GUI app could implement a proper PTY
            
            OutputStream os = shell.getOutputStream();
            int i;
            while ((i = System.in.read()) != -1) {
                os.write(i);
                os.flush();
            }
            os.close();
            
        } finally {
            if (session != null)
                session.close();
            client.disconnect();
        }
    }
    
}
