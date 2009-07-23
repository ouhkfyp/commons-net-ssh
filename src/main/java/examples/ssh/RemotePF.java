package examples.ssh;

import org.apache.commons.net.ssh.SSHClient;
import org.apache.commons.net.ssh.connection.RemotePortForwarding.ConnectListener;
import org.apache.commons.net.ssh.connection.RemotePortForwarding.ForwardedTCPIPChannel;
import org.apache.commons.net.ssh.util.IOUtils;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.PatternLayout;

public class RemotePF
{
    
    static {
        BasicConfigurator.configure(new ConsoleAppender(new PatternLayout("[%t] %p %c{2} %m%n")));
    }
    
    public static void main(String... args) throws Exception
    {
        SSHClient client = new SSHClient();
        client.initUserKnownHosts();
        
        try {
            client.connect("localhost");
            client.authPublickey("shikhar");
            client.startRemoteForwarding("localhost", 8080, new ConnectListener()
                {
                    
                    public void connected(ForwardedTCPIPChannel chan)
                    {
                        System.out.println("New connection from " + chan.getOriginatingIPAddress() + ":"
                                + chan.getOriginatingPort() + " via " + chan.getConnectedAddr() + ":"
                                + chan.getConnectedPort());
                        IOUtils.pipe(chan.getInputStream(), System.out, chan.getLocalMaxPacketSize(), null);
                        IOUtils.pipe(System.in, chan.getOutputStream(), chan.getRemoteMaxPacketSize(), null);
                    }
                    
                });
            client.join(0);
        } finally {
            client.disconnect();
        }
    }
}