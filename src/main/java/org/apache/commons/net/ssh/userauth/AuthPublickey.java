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
import java.security.PublicKey;

import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.Session;
import org.apache.commons.net.ssh.Constants.Message;
import org.apache.commons.net.ssh.keyprovider.KeyProvider;
import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.util.Buffer;

/**
 * Implements the "publickey" SSH authentication method.
 * <p>
 * It is initialised with a {@code Iterator<KeyProvider>}. It first sends a "feeler" request with
 * just the public key, and if the server responds with {@code SSH_MSG_USERAUTH_PK_OK} indicating
 * that the key is acceptable, it proceeds to send a request signed with the private key.
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
     * 
     * @param session
     * @param nextService
     * @param username
     * @param keys
     */
    public AuthPublickey(Session session, Service nextService, String username, KeyProvider kProv)
    {
        super(session, nextService, username, kProv);
    }
    
    /*
     * (non-Javadoc)
     * 
     * @see AuthMethod#getName()
     */
    public String getName()
    {
        return NAME;
    }
    
    /*
     * (non-Javadoc)
     * 
     * @see AbstractAuthMethod#handle(Message, Buffer)
     */
    @Override
    public Result handle(Message cmd, Buffer buf) throws UserAuthException, TransportException
    {
        Result res = super.handle(cmd, buf);
        if (res == Result.UNKNOWN && cmd == Message.USERAUTH_60) {
            sendSignedReq();
            return Result.CONTINUED;
        } else
            return res;
    }
    
    /*
     * (non-Javadoc)
     * 
     * @see AbstractAuthMethod#buildReq()
     */
    @Override
    protected Buffer buildReq() throws UserAuthException
    {
        return buildReq(false);
    }
    
    protected Buffer buildReq(boolean signed) throws UserAuthException
    {
        PublicKey key;
        try {
            key = kProv.getPublic();
        } catch (IOException errWithKeyProv) {
            throw new UserAuthException(errWithKeyProv);
        }
        return buildReqCommon() // generic stuff
                .putBoolean(signed) // indicate whether or not signature is included
                .putPublicKey(key, false); // public key as 2 strings: [ type | blob ]
    }
    
    /**
     * Send signed userauth request
     * 
     * @return {@code true} if all went well, {@code false} if there was an error signing
     */
    private void sendSignedReq() throws UserAuthException, TransportException
    {
        log.debug("Sending signed request");
        
        Buffer reqBuf = buildReq(true);
        
        try {
            reqBuf.putString(signature(new Buffer() // The signature is computed over:
                    .putString(session.getID()) // sessionID string
                    .putBuffer(reqBuf))); // & data from the rest of the request);
        } catch (IOException errWithKeyProv) {
            log.error("While putting signature: {}", errWithKeyProv.toString());
            throw new UserAuthException(errWithKeyProv);
        }
        
        session.writePacket(reqBuf);
    }
    
}
