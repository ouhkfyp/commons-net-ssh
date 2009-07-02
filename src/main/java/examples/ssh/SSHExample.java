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
        client.loadKnownHosts();
        client.connect("127.0.0.1");
        
        client.getAuthBuilder().withPassword("abcdef").authPublickey("/home/shx/.ssh/id_dsa",
                "/home/shx/.ssh/clamv").build().authenticate();
        
        // client.getAuthBuilder().withUsername("bleh").authPassword("abcdef").build().authenticate();
        
        client.disconnect();
        
    }
    
}
