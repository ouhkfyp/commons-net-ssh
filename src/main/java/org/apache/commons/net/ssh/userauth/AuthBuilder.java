package org.apache.commons.net.ssh.userauth;

import java.security.KeyPair;
import java.util.LinkedList;

import org.apache.commons.net.ssh.PasswordFinder;
import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.Session;
import org.apache.commons.net.ssh.keyprovider.KeyPairWrapper;
import org.apache.commons.net.ssh.keyprovider.KeyProvider;

public class AuthBuilder
{
    
    private final Session session;
    
    private final LinkedList<AuthMethod> methods = new LinkedList<AuthMethod>();
    // private final Logger log = LoggerFactory.getLogger(getClass());
    
    private String username;
    private Service nextService;
    
    public AuthBuilder(Session session, Service nextService, String username)
    {
        this.session = session;
        this.nextService = nextService;
        this.username = username;
        //methods.add(new AuthNone(session, nextService, username));
    }
    
    public AuthBuilder authHostbased(String hostuser, String hostname, KeyPair kp)
    {
        return authHostbased(hostuser, hostname, new KeyPairWrapper(kp));
    }
    
    public AuthBuilder authHostbased(String hostuser, String hostname, KeyProvider kProv)
    {
        methods.add(new AuthHostbased(session, nextService, username, hostuser, hostname, kProv));
        return this;
    }
    
    public AuthBuilder authMethod(AuthMethod method)
    {
        methods.add(method);
        return this;
    }
    
    public AuthBuilder authNone()
    {
        methods.add(new AuthNone(session, nextService, username));
        return this;
    }
    
    public AuthBuilder authPassword(PasswordFinder pwdf)
    {
        methods.add(new AuthPassword(session, nextService, username, pwdf));
        return this;
    }
    
    public AuthBuilder authPassword(String password)
    {
        return authPassword(PasswordFinder.Util.createOneOff(password));
    }
    
    public AuthBuilder authPublickey(Iterable<KeyProvider> keyProvs)
    {
        for (KeyProvider kProv : keyProvs)
            authPublickey(kProv);
        return this;
    }
    
    public AuthBuilder authPublickey(KeyPair kp)
    {
        return authPublickey(new KeyPairWrapper(kp));
    }
    
    public AuthBuilder authPublickey(KeyProvider... kProvs)
    {
        for (KeyProvider kProv : kProvs)
            methods.add(new AuthPublickey(session, nextService, username, kProv));
        return this;
    }
    
    public UserAuthService build()
    {
        return new UserAuthProtocol(session, methods);
    }
    
    public AuthBuilder withNextService(Service nextService)
    {
        this.nextService = nextService;
        return this;
    }
    
    public AuthBuilder withUsername(String username)
    {
        this.username = username;
        return this;
    }
    
}
