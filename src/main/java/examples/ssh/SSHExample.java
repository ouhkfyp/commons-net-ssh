package examples.ssh;

import org.apache.commons.net.ssh.SSHClient;
import org.apache.commons.net.ssh.connection.Session;
import org.apache.commons.net.ssh.connection.Session.Command;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.PatternLayout;

public class SSHExample
{
    
    static {
        BasicConfigurator.configure(new ConsoleAppender(new PatternLayout("[%t] %p %c{2} %m%n")));
    }
    
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
            Command cmd = session.exec("true");
            session.waitForClose();
            System.out.println("Exit status: " + cmd.getExitStatus());
        } finally {
            if (session != null)
                session.close();
            client.disconnect();
        }
    }
    
}
