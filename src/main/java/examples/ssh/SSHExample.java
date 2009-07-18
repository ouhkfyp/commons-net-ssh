package examples.ssh;

import org.apache.commons.net.ssh.SSHClient;
import org.apache.commons.net.ssh.connection.Session;
import org.apache.commons.net.ssh.connection.Session.Command;
import org.apache.log4j.BasicConfigurator;

public class SSHExample
{
    
    static {
        BasicConfigurator.configure();
    }
    
    public static void main(String[] args) throws Exception
    {
        
        SSHClient client = new SSHClient();
        
        client.initUserKnownHosts();
        //client.addHostKeyVerifier("e6:d4:18:e6:c8:2d:29:a3:83:ae:aa:d5:fc:f2:49:47");
        
        //client.connect("schmizz.net");
        client.connect("localhost");
        try {
            
            client.authPassword("bobo", "abcdef");
            //            client.authPublickey("shikhar", client.loadKeyFile("/home/shikhar/.ssh/id_rsa"));
            
            Session session = client.startSession();
            session.allocateDefaultPTY();
            Command cmd = session.exec("uptime");
            
            StringBuilder sb = new StringBuilder();
            int r;
            while ((r = cmd.getIn().read()) != -1)
                sb.append((char) r);
            
            System.out.print(sb);
            System.out.println("Exit status: " + cmd.getExitStatus());
            
        } finally {
            client.disconnect();
        }
        
    }
}
