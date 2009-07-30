package examples.ssh;

import java.net.InetSocketAddress;

import org.apache.commons.net.ssh.SSHClient;
import org.apache.commons.net.ssh.connection.LocalPortForwarder;

public class LocalPF
{
    
    //    static {
    //        BasicConfigurator.configure(new ConsoleAppender(new PatternLayout("[%t] %p %c{2} %m%n")));
    //    }
    
    public static void main(String... args) throws Exception
    {
        SSHClient client = new SSHClient();
        
        client.initUserKnownHosts();
        
        client.connect("localhost");
        try {
            
            client.authPublickey(System.getProperty("user.name"));
            
            /*
             * _We_ listen on port localhost:8080 and forward all connections on to server, which
             * then forwards it to google.com:80
             */
            LocalPortForwarder lpf =
                    client.newLocalPortForwarder(new InetSocketAddress("localhost", 8080), "google.com", 80);
            lpf.startListening();
            
            // Something to hang on to
            lpf.join(0);
            
        } finally {
            client.disconnect();
        }
    }
    
}
