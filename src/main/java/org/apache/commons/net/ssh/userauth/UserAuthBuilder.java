package org.apache.commons.net.ssh.userauth;

import java.io.IOException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import org.apache.commons.net.ssh.NamedFactory;
import org.apache.commons.net.ssh.PasswordFinder;
import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.keyprovider.FileKeyProvider;
import org.apache.commons.net.ssh.keyprovider.KeyPairWrapper;
import org.apache.commons.net.ssh.keyprovider.KeyProvider;
import org.apache.commons.net.ssh.transport.Session;
import org.apache.commons.net.ssh.util.SecurityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UserAuthBuilder implements UserAuthService.Builder
{
    
    private final Session session;
    
    private final LinkedList<AuthMethod> methods = new LinkedList<AuthMethod>();
    private final Logger log = LoggerFactory.getLogger(getClass());
    
    private String username;
    private Service nextService;
    private PasswordFinder pwdf;
    
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
    
    public UserAuthBuilder authPassword()
    {
        methods.add(new AuthPassword(session, nextService, username, pwdf));
        return this;
    }
    
    public UserAuthBuilder authPassword(char[] password)
    {
        methods.add(new AuthPassword(session, nextService, username, PasswordFinder.Util
                .createOneOff(password)));
        return this;
    }
    
    public UserAuthBuilder authPassword(String password)
    {
        methods.add(new AuthPassword(session, nextService, username, PasswordFinder.Util
                .createOneOff(password)));
        return this;
    }
    
    public UserAuthBuilder authPublickey(Iterable<KeyProvider> keys)
    {
        return authPublickey(keys.iterator());
    }
    
    public UserAuthBuilder authPublickey(Iterator<KeyProvider> keys)
    {
        methods.add(new AuthPublickey(session, nextService, username, keys));
        return this;
    }
    
    public UserAuthBuilder authPublickey(java.security.KeyPair kp)
    {
        return authPublickey(new KeyPairWrapper(kp));
    }
    
    public UserAuthBuilder authPublickey(KeyProvider... keys)
    {
        if (keys.length > 0)
            return authPublickey(Arrays.asList(keys));
        else
            return this;
    }
    
    public UserAuthBuilder authPublickey(KeyProvider key)
    {
        List<KeyProvider> keys = new LinkedList<KeyProvider>();
        keys.add(key);
        return authPublickey(keys.iterator());
    }
    
    public UserAuthBuilder authPublickey(String... locations)
    { // convenience method, but swallows up errors for API consistency
        List<NamedFactory<FileKeyProvider>> factories = session.getFactoryManager()
                .getFileKeyProviderFactories();
        List<KeyProvider> fkps = new LinkedList<KeyProvider>();
        for (String location : locations)
            try {
                String format = SecurityUtils.detectKeyFileFormat(location);
                if (format.equals("unknown"))
                    throw new IOException("Unknown key file format");
                FileKeyProvider fkp = NamedFactory.Utils.create(factories, format);
                if (fkp != null) {
                    fkp.init(location, pwdf);
                    fkps.add(fkp);
                }
            } catch (IOException e) {
                log.error("Could not add key file at [{}]: {}", location, e.toString());
            }
        if (fkps.size() > 0)
            return authPublickey(fkps);
        else
            return this;
    }
    
    public UserAuthService build()
    {
        return new UserAuth(session, methods);
    }
    
    public UserAuthBuilder withNextService(Service nextService)
    {
        this.nextService = nextService;
        return this;
    }
    
    public UserAuthBuilder withPassword(char[] password)
    {
        pwdf = PasswordFinder.Util.createOneOff(password);
        return this;
    }
    
    public UserAuthBuilder withPassword(PasswordFinder pwdf)
    {
        this.pwdf = pwdf;
        return this;
    }
    
    public UserAuthBuilder withPassword(String password)
    {
        pwdf = PasswordFinder.Util.createOneOff(password);
        return this;
    }
    
    public UserAuthBuilder withUsername(String username)
    {
        this.username = username;
        return this;
    }
    
}
