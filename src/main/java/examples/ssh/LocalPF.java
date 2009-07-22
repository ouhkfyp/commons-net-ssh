package examples.ssh;

import java.net.InetSocketAddress;

import org.apache.commons.net.ssh.SSHClient;
import org.apache.commons.net.ssh.connection.LocalPortForwarding;
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
            client.authPublickey("shikhar");
            // Listens on port 127.0.0.1:9999; and forwards to localhost:22
            LocalPortForwarding pfd =
                    client.startLocalForwarding(new InetSocketAddress("localhost", 9999), "localhost", 22);
            pfd.startListening();
            pfd.join(0);
        } finally {
            client.disconnect();
        }
    }
    
}
