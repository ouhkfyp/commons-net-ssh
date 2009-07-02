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
import org.apache.commons.net.ssh.Constants.Message;
import org.apache.commons.net.ssh.keyprovider.KeyProvider;
import org.apache.commons.net.ssh.transport.Session;
import org.apache.commons.net.ssh.util.Buffer;

public class AuthPublickey extends KeyedAuthMethod
{
    
    public static final String NAME = "publickey";
    
    private final Iterator<KeyProvider> keys;
    
    public AuthPublickey(Session session, Service nextService, String username,
            Iterator<KeyProvider> keys)
    {
        super(session, nextService, username);
        assert keys != null;
        this.keys = keys;
    }
    
    @Override
    protected Buffer buildRequest() throws IOException
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
            if (allowed.contains(NAME) && reqLoop())
                return Result.CONTINUED;
            else
                return buf.getBoolean() ? Result.PARTIAL_SUCCESS : Result.FAILURE;
        case USERAUTH_60:
            log.debug("key acceptable, sending signature");
            try {
                sendSignedReq();
            } catch (IOException e) {
                if (keys.hasNext())
                    log.debug("error sending signing req, trying next: {}", e.toString());
                if (!reqLoop())
                    return Result.FAILURE;
            }
            return Result.CONTINUED;
        default:
            return Result.UNKNOWN;
        }
    }
    
    private boolean reqLoop() throws IOException // returns true if managed to send request
    {
        while (keys.hasNext()) {
            kProv = keys.next();
            try {
                session.writePacket(buildRequest());
            } catch (IOException e) {
                if (keys.hasNext()) {
                    log.debug("had error with last key, trying next: {}", e.toString());
                    continue;
                } else
                    throw e;
            }
            return true;
        }
        return false;
    }
    
    @Override
    public void request() throws IOException
    {
        reqLoop();
    }
    
    private void sendSignedReq() throws IOException
    {
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
