package examples.ssh;

import java.net.InetAddress;
import java.security.PublicKey;

import org.apache.commons.net.ssh.SSHClient;
import org.apache.commons.net.ssh.transport.Session.HostKeyVerifier;
import org.apache.commons.net.ssh.userauth.UserAuthService.PasswordFinder;
import org.apache.commons.net.ssh.util.SecurityUtils;
import org.apache.log4j.BasicConfigurator;

public class SSHExample
{
    
    static {
        BasicConfigurator.configure();
    }
    
    public static void main(String[] args) throws Exception
    {
        
        SSHClient client = new SSHClient();
        
        // still working on support for reading in known_hosts...
        client.setHostKeyVerifier(new HostKeyVerifier()
        {
            public boolean verify(InetAddress address, PublicKey key)
            {
                return "2e:26:99:ec:71:51:ca:a0:b3:1d:3d:10:4c:a7:80:e5".equals(SecurityUtils
                        .getFingerprint(key));
            }
        });
        
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
