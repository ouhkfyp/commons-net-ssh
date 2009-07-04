package org.apache.commons.net.ssh.userauth;

import java.io.IOException;

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
        super(session, nextService, username);
        assert kProv != null;
        this.kProv = kProv;
    }
    
    /**
     * Computes signature over {@code subject}
     * 
     * @param subject
     *            for signature computation
     * @return signature
     * @throws IOException
     *             if there is an error getting private key / key type from key provider
     */
    protected byte[] sign(Buffer subject) throws IOException
    {
        String keyType = kProv.getType().toString();
        Signature sigger = NamedFactory.Utils.create(session.getFactoryManager()
                .getSignatureFactories(), keyType);
        sigger.init(null, kProv.getPrivate());
        sigger.update(subject.getCompactData());
        return new Buffer() // buffer containing signature 
                .putString(keyType) // e.g. ssh-rsa 
                .putString(sigger.sign()) // + the signature
                .getCompactData();
    }
    
}
