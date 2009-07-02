package org.apache.commons.net.ssh.userauth;

import java.io.IOException;
import java.security.PublicKey;

import org.apache.commons.net.ssh.NamedFactory;
import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.keyprovider.KeyProvider;
import org.apache.commons.net.ssh.signature.Signature;
import org.apache.commons.net.ssh.transport.Session;
import org.apache.commons.net.ssh.util.Buffer;

public abstract class KeyedAuthMethod extends AbstractAuthMethod
{
    protected KeyProvider kProv;
    
    public KeyedAuthMethod(Session session, Service nextService, String username)
    {
        super(session, nextService, username);
    }
    
    public KeyedAuthMethod(Session session, Service nextService, String username, KeyProvider kPair)
    {
        this(session, nextService, username);
        assert kPair != null;
        kProv = kPair;
    }
    
    protected Buffer putPubKey(Buffer target) throws IOException
    {
        PublicKey key = kProv.getPublic();
        target.putString(kProv.getType().toString());
        Buffer temp = new Buffer();
        temp.putPublicKey(key);
        target.putString(temp.getCompactData());
        return target;
    }
    
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
