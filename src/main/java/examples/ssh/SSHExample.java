package examples.ssh;

import java.io.InputStreamReader;

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
    
    public static void main(String[] args) throws Exception
    {
        
        SSHClient client = new SSHClient();
        
        client.initUserKnownHosts();
        //        client.addHostKeyVerifier("e6:d4:18:e6:c8:2d:29:a3:83:ae:aa:d5:fc:f2:49:47");
        
        long startTime = System.nanoTime();
        
        //        client.connect("localhost");
        client.connect("schmizz.net");
        Session session = null;
        try {
            
            //            client.authPassword("bobo", "acdef".toCharArray());
            client.authPublickey("shikhar", client.loadKeyFile("/home/shikhar/.ssh/id_rsa"));
            session = client.startSession();
            Command cmd = session.exec("man ssh_config");
            
            StringBuilder sb = new StringBuilder();
            InputStreamReader reader = new InputStreamReader(cmd.getInputStream());
            int read;
            char[] cbuf = new char[256];
            while ((read = reader.read(cbuf)) != -1)
                sb.append(cbuf, 0, read);
            
            //            System.out.print(client.getAuthBanner());
            System.out.print(sb);
            System.out.println("Exit status: " + cmd.getExitStatus());
            
        } finally {
            System.out.println("*** took " + (System.nanoTime() - startTime) / 1000000000.0 + " seconds.");
            if (session != null)
                session.close();
            client.disconnect();
        }
        
    }
}
