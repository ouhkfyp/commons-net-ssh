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
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;

import org.apache.commons.net.ssh.NamedFactory;
import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.signature.Signature;
import org.apache.commons.net.ssh.transport.Session;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Constants;

public class AuthPublickey extends AbstractAuthMethod
{
    
    public static final String NAME = "publickey";
    private final KeyPair kp;
    
    public AuthPublickey(Session session, Service nextService, String username, KeyPair kp)
    {
        super(session, nextService, username);
        assert kp != null;
        this.kp = kp;
    }
    
    @Override
    protected Buffer buildRequest()
    {
        Buffer buf = buildRequestCommon(session
                .createBuffer(Constants.Message.SSH_MSG_USERAUTH_REQUEST));
        buf.putBoolean(false);
        putPublicKey(buf);
        return buf;
    }
    
    public String getName()
    {
        return NAME;
    }
    
    public Result handle(Constants.Message cmd, Buffer buf) throws IOException
    {
        switch (cmd)
        {
        case SSH_MSG_USERAUTH_SUCCESS:
            return Result.SUCCESS;
        case SSH_MSG_USERAUTH_FAILURE:
            setAllowedMethods(buf.getString());
            return Result.FAILURE;
        case SSH_MSG_USERAUTH_60:
            log.debug("Key acceptable, sending signature");
            sendSignedRequest();
            return Result.CONTINUED;
        default:
            log.error("Unexpected packet");
            return Result.FAILURE;
        }
    }
    
    private void putPublicKey(Buffer buf)
    {
        PublicKey key = kp.getPublic();
        if (key instanceof RSAPublicKey)
            buf.putString(Constants.SSH_RSA);
        else if (key instanceof DSAPublicKey)
            buf.putString(Constants.SSH_RSA);
        else
            assert false;
        
        Buffer temp = new Buffer();
        temp.putPublicKey(key);
        buf.putString(temp.getCompactData());
    }
    
    private void sendSignedRequest() throws IOException
    {
        Signature sig = NamedFactory.Utils.create(session.getFactoryManager()
                .getSignatureFactories(), "ssh-rsa");
        sig.init(null, kp.getPrivate());
        
        Buffer buf = buildRequestCommon(session
                .createBuffer(Constants.Message.SSH_MSG_USERAUTH_REQUEST));
        buf.putBoolean(true);
        putPublicKey(buf);
        
        sig.update(session.getID());
        sig.update(buf.getCompactData());
        buf.putString(sig.sign());
        
        session.writePacket(buf);
        
    }
}
