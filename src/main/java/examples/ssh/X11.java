package examples.ssh;

import java.net.InetSocketAddress;

import org.apache.commons.net.ssh.SSHClient;
import org.apache.commons.net.ssh.connection.Session;
import org.apache.commons.net.ssh.connection.ConnectListener.SocketForwardingConnectListener;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.PatternLayout;

public class X11
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
            
            Session sess = client.startSession();
            sess.startX11Forwarding(false, "MIT-MAGIC-COOKIE-1", "50450f76cbd53589c65a8eec5b597197", 0,
                                    new SocketForwardingConnectListener(new InetSocketAddress("localhost", 6000)));
            
            sess.exec("firefox");
            
            client.getConnectionService().join();
            
        } finally {
            client.disconnect();
        }
        
    }
}