package examples.ssh;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

import org.apache.commons.net.ssh.SSHClient;
import org.apache.commons.net.ssh.connection.RemotePortForwarder.ConnectListener;
import org.apache.commons.net.ssh.connection.RemotePortForwarder.ForwardedTCPIPChannel;
import org.apache.commons.net.ssh.connection.RemotePortForwarder.Forward;
import org.apache.commons.net.ssh.util.Pipe;
import org.apache.commons.net.ssh.util.Pipe.ErrorCallback;
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
        
        client.connect("localhost");
        try {
            client.authPublickey(System.getProperty("user.name"));
            client.getRemotePortForwarder().bind(new Forward(8080), new ConnectListener()
                {
                    
                    public void gotConnect(ForwardedTCPIPChannel chan) throws IOException
                    {
                        Socket sock = new Socket();
                        sock.connect(new InetSocketAddress("google.com", 80));
                        System.out.println("New connection from " + chan.getOriginatingIP() + ":"
                                + chan.getOriginatingPort() + " on " + chan.getParentForward());
                        
                        ErrorCallback chanCloser = Pipe.closeOnErrorCallback(chan);
                        
                        Pipe sock2chan = new Pipe(sock.getInputStream(), chan.getOutputStream());
                        sock2chan.eofCallback(Pipe.closeOnEOFCallback(chan.getOutputStream()));
                        sock2chan.errorCallback(chanCloser);
                        sock2chan.bufSize(chan.getRemoteMaxPacketSize());
                        
                        Pipe chan2sock = new Pipe(chan.getInputStream(), sock.getOutputStream());
                        chan2sock.eofCallback(Pipe.closeOnEOFCallback(sock.getOutputStream()));
                        chan2sock.errorCallback(chanCloser);
                        chan2sock.bufSize(chan.getLocalMaxPacketSize());
                        
                        sock2chan.start();
                        chan2sock.start();
                        
                    }
                    
                });
            client.join(0);
        } finally {
            client.disconnect();
        }
    }
}