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

import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.Session;
import org.apache.commons.net.ssh.TransportException;
import org.apache.commons.net.ssh.keyprovider.KeyProvider;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Constants.Message;

/**
 * Implements the {@code "publickey"} SSH authentication method.
 * <p>
 * It is initialised with a {@code KeyProvider>}. It first sends a "feeler" request with just the
 * public key, and if the server responds with {@code SSH_MSG_USERAUTH_PK_OK} indicating that the
 * key is acceptable, it proceeds to send a request signed with the private key.
 * 
 * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
 */
public class AuthPublickey extends KeyedAuthMethod
{
    
    /**
     * Assigned name of this authentication method
     */
    public static final String NAME = "publickey";
    
    public AuthPublickey(Session session, Service nextService, String username, KeyProvider kProv)
    {
        super(session, nextService, username, kProv);
    }
    
    public String getName()
    {
        return NAME;
    }
    
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
    
    private void sendSignedReq() throws UserAuthException, TransportException
    {
        log.debug("Sending signed request");
        session.writePacket(putSig(buildReq(true)));
    }
    
    @Override
    protected Buffer buildReq() throws UserAuthException
    {
        return buildReq(false);
    }
    
    protected Buffer buildReq(boolean signed) throws UserAuthException
    {
        try {
            kProv.getPublic();
        } catch (IOException ioe) {
            throw new UserAuthException("Problem getting public key", ioe);
        }
        return putPubKey(super.buildReq().putBoolean(signed));
    }
    
}
