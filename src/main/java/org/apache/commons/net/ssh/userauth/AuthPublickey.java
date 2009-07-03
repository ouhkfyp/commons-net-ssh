/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.commons.net.ssh.userauth;

import java.io.IOException;
import java.util.Iterator;

import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.Session;
import org.apache.commons.net.ssh.Constants.Message;
import org.apache.commons.net.ssh.keyprovider.KeyProvider;
import org.apache.commons.net.ssh.util.Buffer;

/**
 * Implements the "publickey" SSH authentication method.
 * <p>
 * It is initialised with an {@code Iterator<KeyProvider>}. It sends "feeler" requests using just
 * the public key from the key provider, until the server responds with {@code
 * SSH_MSG_USERAUTH_PK_OK} indicating that the key is acceptable. Then it proceeds to send a request
 * signed with the private key.
 * <p>
 * At any point if there is an error and there are more key providers available in the iterator, it
 * silently logs the error and continues.
 * 
 * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
 */
public class AuthPublickey extends KeyedAuthMethod
{
    
    /**
     * Assigned name of this authentication method
     */
    public static final String NAME = "publickey";
    
    /**
     * KeyProvider's that we shall try
     */
    private final Iterator<KeyProvider> keys;
    
    /**
     * 
     * @param session
     * @param nextService
     * @param username
     * @param keys
     */
    public AuthPublickey(Session session, Service nextService, String username,
            Iterator<KeyProvider> keys)
    {
        super(session, nextService, username);
        assert keys != null;
        this.keys = keys;
    }
    
    /*
     * (non-Javadoc)
     * 
     * @see org.apache.commons.net.ssh.userauth.AuthMethod#getName()
     */
    public String getName()
    {
        return NAME;
    }
    
    /*
     * (non-Javadoc)
     * 
     * @see
     * org.apache.commons.net.ssh.userauth.AbstractAuthMethod#handle(org.apache.commons.net.ssh.
     * Constants.Message, org.apache.commons.net.ssh.util.Buffer)
     */
    @Override
    public Result handle(Message cmd, Buffer buf) throws IOException
    {
        switch (cmd)
        {
        case USERAUTH_SUCCESS:
            return Result.SUCCESS;
        case USERAUTH_FAILURE:
            setAllowedMethods(buf.getString());
            if (allowed.contains(NAME) && reqLoop())
                // publickey auth still available, and managed to send another feeler
                return Result.CONTINUED;
            else
                // a true value here indicates "partial success" (more auths needed)
                return buf.getBoolean() ? Result.PARTIAL_SUCCESS : Result.FAILURE;
        case USERAUTH_60:
            log.info("Key acceptable, sending signature");
            try {
                sendSignedReq();
            } catch (IOException e) {
                log.debug("Error sending signed req: {}", e.toString());
                if (!reqLoop())
                    return Result.FAILURE;
            }
            return Result.CONTINUED;
        default:
            return Result.UNKNOWN;
        }
    }
    
    /*
     * (non-Javadoc)
     * 
     * @see org.apache.commons.net.ssh.userauth.AbstractAuthMethod#request()
     */
    @Override
    public void request() throws IOException // initially invoked by UserAuthProtocol
    {
        if (!reqLoop())
            throw new UserAuthException("Got no keys to try");
    }
    
    @Override
    protected Buffer buildReq() throws IOException
    {
        // the false indicates that this is not a signed request just yet
        // putPubKey puts < key ident | key blob > and returns back buffer
        return putPubKey(buildReqCommon().putBoolean(false));
    }
    
    /**
     * Send a feeler request, and don't give up till out of keys
     * 
     * @return {@code true} indicates a request was sent, {@code false} that no more keys
     * @throws IOException
     *             out of keys + an error occured in the last request
     */
    private boolean reqLoop() throws IOException
    {
        while (keys.hasNext()) {
            kProv = keys.next();
            try {
                log.debug("Sending request for {} key", kProv.getType());
                session.writePacket(buildReq());
            } catch (IOException e) {
                if (keys.hasNext()) {
                    log.debug("Had error with last key, trying next: {}", e.toString());
                    continue;
                } else
                    throw e;
            }
            return true;
        }
        return false;
    }
    
    /**
     * Send signed userauth request
     * 
     * @throws IOException
     */
    private void sendSignedReq() throws IOException
    {
        // this is the request buffer, to which we will add the signature in a bit
        Buffer reqBuf = buildReqCommon().putBoolean(true);
        putPubKey(reqBuf);
        
        // the subject for the signature: consists of sessionID string + above data
        Buffer sigSubj = new Buffer().putString(session.getID()).putBuffer(reqBuf);
        
        // putSig returns reqBuf back after adding signature
        session.writePacket(putSig(sigSubj, reqBuf));
    }
    
}
