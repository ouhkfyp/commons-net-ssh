package examples.ssh;

import java.net.InetSocketAddress;

import org.apache.commons.net.ssh.SSHClient;
import org.apache.commons.net.ssh.connection.LocalPortForwarder;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.PatternLayout;

public class LocalPF
{
    
    static {
        BasicConfigurator.configure(new ConsoleAppender(new PatternLayout("[%t] %p %c{2} %m%n")));
    }
    
    public static void main(String... args) throws Exception
    {
        SSHClient client = new SSHClient();
        client.initUserKnownHosts();
        client.connect("localhost");
        try {
            client.authPublickey(System.getProperty("user.name"));
            // Listens on port localhost:8080 and forwards to google.com:80
            LocalPortForwarder pfd =
                    client.startLocalPortForwarding(new InetSocketAddress("localhost", 8080), "google.com", 80);
            pfd.startListening();
            pfd.join(0);
        } finally {
            client.disconnect();
        }
    }
    
}
