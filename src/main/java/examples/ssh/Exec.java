package examples.ssh;

import java.io.BufferedReader;
import java.io.InputStreamReader;

import org.apache.commons.net.ssh.SSHClient;
import org.apache.commons.net.ssh.connection.Session;
import org.apache.commons.net.ssh.connection.Session.Command;

public class Exec
{
    
    //    static {
    //        BasicConfigurator.configure(new ConsoleAppender(new PatternLayout("[%t] %p %c{2} %m%n")));
    //    }
    
    public static void main(String... args) throws Exception
    {
        SSHClient client = new SSHClient();
        client.initUserKnownHosts();
        client.connect("localhost");
        Session session = null;
        try {
            client.authPublickey(System.getProperty("user.name"));
            session = client.startSession();
            session.allocateDefaultPTY();
            Command cmd = session.exec("uptime");
            
            BufferedReader br = new BufferedReader(new InputStreamReader(cmd.getInputStream()));
            String line;
            while ((line = br.readLine()) != null)
                System.out.print(line);
            
            // wait for channel to get closed so we can be sure we have received exit status
            client.getConnectionService().join();
            System.out.println("\nExit status: " + cmd.getExitStatus());
        } finally {
            if (session != null)
                session.close();
            client.disconnect();
        }
    }
    
}
