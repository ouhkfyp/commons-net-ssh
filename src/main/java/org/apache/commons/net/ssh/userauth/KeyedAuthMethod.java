package org.apache.commons.net.ssh.userauth;

import java.io.IOException;
import java.security.PublicKey;

import org.apache.commons.net.ssh.NamedFactory;
import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.Session;
import org.apache.commons.net.ssh.keyprovider.KeyProvider;
import org.apache.commons.net.ssh.signature.Signature;
import org.apache.commons.net.ssh.util.Buffer;

public abstract class KeyedAuthMethod extends AbstractAuthMethod
{
    protected KeyProvider kProv;
    
    /**
     * Constructor; does not initialize a specific key provider
     * 
     * @param session
     * @param nextService
     * @param username
     */
    public KeyedAuthMethod(Session session, Service nextService, String username)
    {
        super(session, nextService, username);
    }
    
    /**
     * Constructor; initializes a specific key provider
     * 
     * @param session
     *            transport layer
     * @param nextService
     *            service to start on successful auth
     * @param username
     *            username for this authentication attempt
     * @param kProv
     *            key provider
     */
    public KeyedAuthMethod(Session session, Service nextService, String username, KeyProvider kProv)
    {
        this(session, nextService, username);
        assert kProv != null;
        this.kProv = kProv;
    }
    
    /**
     * Put public key spec into the supplied {@link Buffer} - the key type as a string followed by
     * the public key blob as a string.
     * 
     * @param target
     *            the buffer in which to put the public key
     * @return the target, now containing the public key fields
     * @throws IOException
     */
    protected Buffer putPubKey(Buffer target) throws IOException
    {
        PublicKey key = kProv.getPublic();
        target.putString(kProv.getType().toString());
        Buffer temp = new Buffer();
        temp.putPublicKey(key);
        target.putString(temp.getCompactData());
        return target;
    }
    
    /**
     * Compute signature over {@code subject} and put the signature into {@code target}.
     * 
     * @param subject
     *            for signature computation
     * @param target
     *            into which to put the signature
     * @return the target, now containing the signature
     * @throws IOException
     */
    protected Buffer putSig(Buffer subject, Buffer target) throws IOException
    {
        Signature sig = NamedFactory.Utils.create(session.getFactoryManager()
                .getSignatureFactories(), kProv.getType().toString());
        sig.init(null, kProv.getPrivate());
        sig.update(subject.getCompactData());
        
        // buffer containing signature
        Buffer sigBuf = new Buffer();
        sigBuf.putString(kProv.getType().toString());
        sigBuf.putString(sig.sign());
        
        target.putString(sigBuf.getCompactData());
        
        return target;
    }
    
}
