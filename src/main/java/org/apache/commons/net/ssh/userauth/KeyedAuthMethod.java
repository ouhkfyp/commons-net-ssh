package org.apache.commons.net.ssh.userauth;

import java.security.KeyPair;
import java.security.PublicKey;

import org.apache.commons.net.ssh.NamedFactory;
import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.Constants.KeyType;
import org.apache.commons.net.ssh.signature.Signature;
import org.apache.commons.net.ssh.transport.Session;
import org.apache.commons.net.ssh.util.Buffer;

public abstract class KeyedAuthMethod extends AbstractAuthMethod
{
    protected final KeyPair kPair;
    protected final String kType;
    
    public KeyedAuthMethod(Session session, Service nextService, String username, KeyPair kp)
    {
        super(session, nextService, username);
        assert kp != null;
        kPair = kp;
        kType = KeyType.fromKey(kp.getPrivate()).toString();
    }
    
    /**
     * 
     * @param into
     * @return
     */
    protected Buffer putPubKey(Buffer into)
    {
        PublicKey key = kPair.getPublic();
        into.putString(kType);
        Buffer temp = new Buffer();
        temp.putPublicKey(key);
        into.putString(temp.getCompactData());
        return into;
    }
    
    /**
     * 
     * @param over
     * @param into
     * @return
     */
    protected Buffer putSig(Buffer over, Buffer into)
    {
        Signature sig = NamedFactory.Utils.create(session.getFactoryManager()
                .getSignatureFactories(), kType);
        sig.init(null, kPair.getPrivate());
        sig.update(over.getCompactData());
        
        // buffer containing signature
        Buffer sigBuf = new Buffer();
        sigBuf.putString(kType.toString());
        sigBuf.putString(sig.sign());
        
        into.putString(sigBuf.getCompactData());
        
        return into;
    }
    
}
