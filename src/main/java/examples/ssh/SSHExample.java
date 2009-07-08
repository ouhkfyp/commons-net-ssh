package examples.ssh;

import org.apache.commons.net.ssh.SSHClient;
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
        
        client.connect("localhost");
        
        client.authPassword("bobo", "abcdef");
        
        //        // PUBLICKEY AUTH
        //        KeyProvider fkp = client.loadKeyFile("/home/shikhar/.ssh/clamv");
        //        client.getAuthBuilder().authPublickey(fkp).build().authenticate();
        
        //        // HOSTBASED AUTH
        //        KeyProvider fkp = client.loadKeyFile("/home/shikhar/ssh_host_rsa_key");
        //        client.getAuthBuilder().authHostbased("bobo", "localhost.localdomain", fkp).build().authenticate();
        
        client.disconnect();
        
    }
}
