package examples.ssh;

import java.io.InputStreamReader;

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
        //        client.addHostKeyVerifier("e6:d4:18:e6:c8:2d:29:a3:83:ae:aa:d5:fc:f2:49:47");
        
        //        client.connect("schmizz.net");
        long startTime = System.nanoTime();
        
        client.connect("localhost");
        try {
            
            //            client.authPassword("bobo", "abcdef".toCharArray());
            client.authPublickey("shikhar", client.loadKeyFile("/home/shikhar/.ssh/id_rsa"));
            
            Session session = client.startSession();
            Command cmd = session.exec("man ls");
            
            StringBuilder sb = new StringBuilder();
            InputStreamReader reader = new InputStreamReader(cmd.getIn());
            int read;
            char[] cbuf = new char[256];
            while ((read = reader.read(cbuf)) != -1)
                sb.append(cbuf, 0, read);
            
            System.out.print(sb);
            System.out.println("Exit status: " + cmd.getExitStatus());
            
        } finally {
            System.out.println("*** took " + (System.nanoTime() - startTime) / 1000000000.0 + " seconds.");
            client.disconnect();
        }
        
    }
}
