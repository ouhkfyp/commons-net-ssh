package org.apache.commons.net.ssh.userauth;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.commons.net.ssh.NamedFactory;
import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.Session;
import org.apache.commons.net.ssh.keyprovider.KeyProvider;
import org.apache.commons.net.ssh.signature.Signature;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Constants.KeyType;

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
    
    protected Buffer putPubKey(Buffer reqBuf) throws UserAuthException
    {
        PublicKey key;
        try {
            key = kProv.getPublic();
        } catch (IOException ioe) {
            throw new UserAuthException("Problem getting public key", ioe);
        }
        
        // public key as 2 strings: [ key type | key blob ]
        reqBuf.putString(KeyType.fromKey(key).toString()) //
              .putString(new Buffer().putPublicKey(key).getCompactData());
        
        return reqBuf;
    }
    
    protected Buffer putSig(Buffer reqBuf) throws UserAuthException
    {
        PrivateKey key;
        try {
            key = kProv.getPrivate();
        } catch (IOException ioe) {
            throw new UserAuthException("Problem getting private key", ioe);
        }
        String kt = KeyType.fromKey(key).toString();
        Signature sigger = NamedFactory.Utils.create(session.getFactoryManager()
                                                            .getSignatureFactories(), kt);
        sigger.init(null, key);
        sigger.update(new Buffer().putString(session.getID()) // sessionID string
                                  .putBuffer(reqBuf) // & the data from common request stuff
                                  .getCompactData());
        reqBuf.putSignature(kt, sigger.sign());
        return reqBuf;
    }
    
}
