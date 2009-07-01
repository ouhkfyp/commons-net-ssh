package examples.ssh;

import org.apache.commons.net.ssh.SSHClient;
import org.apache.commons.net.ssh.userauth.UserAuthService.PasswordFinder;
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
        client.connect("localhost");
        client.getAuthBuilder().withUsername("bleh").authPassword(new PasswordFinder()
        {
            public char[] getPassword()
            {
                return "abcdef".toCharArray();
            }
        }).build().authenticate();
        client.disconnect();
    }
}
