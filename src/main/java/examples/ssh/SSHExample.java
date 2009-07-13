package examples.ssh;

import org.apache.commons.net.ssh.SSHClient;
import org.apache.commons.net.ssh.keyprovider.KeyProvider;
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
        //client.addHostKeyVerifier("c1:32:d6:5d:28:ed:c5:2c:8a:96:47:d8:dc:56:e3:80");
        
        client.connect("localhost");
        try {
            
            // client.authPassword("bobo", "abcdef");
            
            KeyProvider fkp = client.loadKeyFile("/home/shikhar/.ssh/id_rsa");
            client.authPublickey("shikhar", fkp);
            
        } finally {
            client.disconnect();
        }
        
    }
    
}
