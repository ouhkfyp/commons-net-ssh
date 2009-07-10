package org.apache.commons.net.ssh.userauth;

import java.util.LinkedList;

import org.apache.commons.net.ssh.PasswordFinder;
import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.Session;
import org.apache.commons.net.ssh.keyprovider.KeyProvider;

/**
 * A builder for {@link UserAuthProtocol} that eases object construction with method-chaining.
 * <p>
 * Multiple authentication methods can be specified, and the instance of {@link UserAuthService}
 * that is built will try these in order.
 * 
 * @author shikhar
 */
public class AuthBuilder
{
    
    private final Session session;
    
    private final LinkedList<AuthMethod> methods = new LinkedList<AuthMethod>();
    // private final Logger log = LoggerFactory.getLogger(getClass());
    
    private String username;
    private Service nextService;
    
    /**
     * Constructor for this builder that accepts arguments which are mandatorily required for any
     * authentication method.
     * 
     * @param session
     *            the transport layer instance
     * @param nextService
     *            the next service that is to be started on successful authentication
     * @param username
     *            the username that has to be authenticated
     */
    public AuthBuilder(Session session, Service nextService, String username)
    {
        this.session = session;
        this.nextService = nextService;
        this.username = username;
        //methods.add(new AuthNone(session, nextService, username));
    }
    
    /**
     * Specifies that {@code "hostbased"} authentication should be tried.
     * 
     * @param hostuser
     * @param hostname
     * @param kProv
     * @return {@code this}
     */
    public AuthBuilder authHostbased(String hostuser, String hostname, KeyProvider kProv)
    {
        methods.add(new AuthHostbased(session, nextService, username, hostuser, hostname, kProv));
        return this;
    }
    
    /**
     * Specifies that the given {@code method}'s should be tried.
     * 
     * @param method
     *            authentication method
     * @return {@code this}
     */
    public AuthBuilder authMethod(AuthMethod... methods)
    {
        for (AuthMethod meth : methods)
            this.methods.add(meth);
        return this;
    }
    
    /**
     * Specifies that {@code "none"} authentication should be tried.
     * 
     * @return {@code this}
     */
    public AuthBuilder authNone()
    {
        methods.add(new AuthNone(session, nextService, username));
        return this;
    }
    
    /**
     * Specifies that {@code "password"} authentication should be tried, using the supplied
     * {@link PasswordFinder}.
     * 
     * @param pwdf
     *            the {@link PasswordFinder}
     * @return {@code this}
     */
    public AuthBuilder authPassword(PasswordFinder pwdf)
    {
        methods.add(new AuthPassword(session, nextService, username, pwdf));
        return this;
    }
    
    /**
     * Specifies that {@code "password"} authentication should be tried, using the supplied {@code
     * password} string.
     * 
     * @param password
     *            the password
     * @return {@code this}
     */
    public AuthBuilder authPassword(String password)
    {
        return authPassword(PasswordFinder.Util.createOneOff(password));
    }
    
    /**
     * Specifies that {@code "publickey"} authentication should be tried using the supplied
     * {@link KeyProvider}(s)
     * 
     * @param kProvs
     * @return {@code this}
     */
    public AuthBuilder authPublickey(KeyProvider... kProvs)
    {
        for (KeyProvider kProv : kProvs)
            methods.add(new AuthPublickey(session, nextService, username, kProv));
        return this;
    }
    
    /**
     * Builds a {@code UserAuthService} instance.
     * 
     * @return the constructed {@link UserAuthService}
     */
    public UserAuthService build()
    {
        return new UserAuthProtocol(session, methods);
    }
    
    /**
     * Specify the next {@link Service} to request in authentication requests; applicable for all
     * following invocations on this instance that specify an authentication method.
     * 
     * @param nextService
     * @return {@code this}
     */
    public AuthBuilder withNextService(Service nextService)
    {
        this.nextService = nextService;
        return this;
    }
    
    /**
     * Specify the username to request in authentication requests; applicable for all following
     * invocations on this instance that specify an authentication method.
     * 
     * @param username
     *            the username
     * @return {@code this}
     */
    public AuthBuilder withUsername(String username)
    {
        this.username = username;
        return this;
    }
    
}
