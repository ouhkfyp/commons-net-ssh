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

import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.Constants.KeyType;
import org.apache.commons.net.ssh.Constants.Message;
import org.apache.commons.net.ssh.transport.Session;
import org.apache.commons.net.ssh.util.Buffer;

public class AuthPublickey extends KeyedAuthMethod
{
    
    public static final String NAME = "publickey";
    
    public AuthPublickey(Session session, Service nextService, String username, KeyPair kp)
    {
        super(session, nextService, username, kp);
    }
    
    @Override
    protected Buffer buildRequest()
    {
        Buffer buf = buildRequestCommon(new Buffer(Message.USERAUTH_REQUEST));
        buf.putBoolean(false);
        putPubKey(buf);
        return buf;
    }
    
    public String getName()
    {
        return NAME;
    }
    
    @Override
    public Result handle(Message cmd, Buffer buf) throws IOException
    {
        switch (cmd)
        {
        case USERAUTH_SUCCESS:
            return Result.SUCCESS;
        case USERAUTH_FAILURE:
            setAllowedMethods(buf.getString());
            if (buf.getBoolean())
                return Result.PARTIAL_SUCCESS;
            else
                return Result.FAILURE;
        case USERAUTH_60:
            log.debug("Key acceptable, sending signature");
            sendSignedReq();
            return Result.CONTINUED;
        default:
            log.error("Unexpected packet");
            return Result.FAILURE;
        }
    }
    
    private void sendSignedReq() throws IOException
    {
        KeyType.fromKey(kPair.getPublic());
        
        // this is the request buffer, to which we will add the signature in a bit
        Buffer reqBuf = buildRequestCommon(new Buffer(Message.USERAUTH_REQUEST));
        reqBuf.putBoolean(true);
        putPubKey(reqBuf);
        
        // the subject for the signature: consists of sessionID string + above data
        Buffer sigSubj = new Buffer();
        sigSubj.putString(session.getID());
        sigSubj.putBuffer(reqBuf);
        
        // ready to go
        session.writePacket(putSig(sigSubj, reqBuf));
    }
}
