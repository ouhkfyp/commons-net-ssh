package org.apache.commons.net.ssh.userauth;

import java.io.FileNotFoundException;
import java.security.KeyPair;
import java.util.LinkedList;

import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.transport.Session;
import org.apache.commons.net.ssh.userauth.AuthPassword.ChangeRequestHandler;
import org.apache.commons.net.ssh.userauth.UserAuthService.PasswordFinder;
import org.apache.commons.net.ssh.util.SecurityUtils;

public class UserAuthBuilder implements UserAuthService.Builder
{
    private final Session session;
    private final LinkedList<AuthMethod> methods = new LinkedList<AuthMethod>();
    private String username;
    private Service nextService;
    private boolean lookForKeys;
    
    {
        if (SecurityUtils.isBouncyCastleRegistered())
            lookForKeys = true;
    }
    
    public UserAuthBuilder(Session session, String username, Service nextService)
    {
        this.session = session;
        this.username = username;
        this.nextService = nextService;
    }
    
    public UserAuthBuilder authMethod(AuthMethod method)
    {
        methods.add(method);
        return this;
    }
    
    public UserAuthBuilder authPassword(PasswordFinder pwdf)
    {
        return authPassword(pwdf, null);
    }
    
    public UserAuthBuilder authPassword(PasswordFinder pwdf, ChangeRequestHandler crh)
    {
        methods.add(new AuthPassword(session, nextService, username, pwdf, crh));
        return this;
    }
    
    public UserAuthBuilder authPublickey(KeyPair kp)
    {
        methods.add(new AuthPublickey(session, nextService, username, kp));
        return this;
    }
    
    public UserAuthBuilder authPublickey(String loc) throws FileNotFoundException
    {
        return authPublickey(new String[] { loc });
    }
    
    public UserAuthBuilder authPublickey(String... locs) throws FileNotFoundException
    {
        // TODO: read in KeyPair's using org.bc.openssl.PEMReader and add each as a new
        // AuthPublickey
        return this;
    }
    
    public UserAuthService build()
    {
        return new UserAuth(session, methods);
    }
    
    public UserAuthBuilder lookForKeys(boolean lookForKeys)
    {
        this.lookForKeys = lookForKeys;
        return this;
    }
    
    public UserAuthBuilder withNextService(Service nextService)
    {
        this.nextService = nextService;
        return this;
    }
    
    public UserAuthBuilder withUsername(String username)
    {
        this.username = username;
        return this;
    }
    
}
