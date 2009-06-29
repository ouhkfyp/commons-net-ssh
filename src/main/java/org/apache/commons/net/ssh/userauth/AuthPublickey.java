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

import org.apache.commons.net.ssh.NamedFactory;
import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.signature.Signature;
import org.apache.commons.net.ssh.transport.Session;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Constants.KeyType;
import org.apache.commons.net.ssh.util.Constants.Message;

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
        Buffer buf = buildRequestCommon(session.createBuffer(Message.SSH_MSG_USERAUTH_REQUEST));
        buf.putBoolean(false);
        putPublicKey(buf);
        return buf;
    }
    
    public String getName()
    {
        return NAME;
    }
    
    public Result handle(Message cmd, Buffer buf) throws IOException
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
        buf.putString(KeyType.fromKey(key).toString());
        
        Buffer temp = new Buffer();
        temp.putPublicKey(key);
        buf.putString(temp.getCompactData());
    }
    
    private void sendSignedRequest() throws IOException
    {
        KeyType type = KeyType.fromKey(kp.getPublic());
        
        Signature sig = NamedFactory.Utils.create(session.getFactoryManager()
                .getSignatureFactories(), type.toString());
        sig.init(kp.getPublic(), kp.getPrivate());
        
        Buffer reqBuf = buildRequestCommon(session.createBuffer(Message.SSH_MSG_USERAUTH_REQUEST));
        reqBuf.putBoolean(true);
        putPublicKey(reqBuf);
        
        Buffer sigSubj = new Buffer();
        sigSubj.putString(session.getID());
        sigSubj.putBuffer(reqBuf);
        sig.update(sigSubj.getCompactData());
        
        Buffer sigBuf = new Buffer();
        sigBuf.putString(type.toString());
        sigBuf.putString(sig.sign());
        
        reqBuf.putString(sigBuf.getCompactData());
        
        session.writePacket(reqBuf);
    }
}
