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

import org.apache.commons.net.ssh.Constants;
import org.apache.commons.net.ssh.transport.Session;
import org.apache.commons.net.ssh.util.Buffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MethPassword implements Method
{
    public interface ChangeRequestHandler
    {
        char[] getNewPassword();
        
        char[] getOldPassword();
        
        void notifyFailure();
        
        void notifySuccess();
        
        ChangeRequestHandler notifyUnacceptable();
        
        void setPrompt(String prompt);
    }
    
    public static final String NAME = "password";
    
    private final Logger log = LoggerFactory.getLogger(getClass());
    private final Session session;
    private final String username;
    private final String nextService;
    private final PasswordFinder pwdf;
    
    private String[] allowed;
    private ChangeRequestHandler crh;
    private boolean changeRequested = false;
    
    // crh may be null
    public MethPassword(Session session, String username, String nextService, PasswordFinder pwdf,
            ChangeRequestHandler crh)
    {
        this.session = session;
        this.username = username;
        this.nextService = nextService;
        this.pwdf = pwdf;
        this.crh = crh;
    }
    
    public void buildRequest(Buffer buf)
    {
        buildRequestCommon(buf);
        buf.putBoolean(false);
        buf.putString(pwdf.getPassword());
    }
    
    private void buildRequestCommon(Buffer buf)
    {
        buf.putString(username);
        buf.putString(nextService);
        buf.putString(NAME);
    }
    
    public String[] getAllowedMethods()
    {
        return allowed;
    }
    
    public String getName()
    {
        return NAME;
    }
    
    public Result next(Constants.Message cmd, Buffer buf) throws IOException
    {
        switch (cmd)
        {
        case SSH_MSG_USERAUTH_SUCCESS:
            if (changeRequested)
                crh.notifySuccess();
            return Result.SUCCESS;
        case SSH_MSG_USERAUTH_FAILURE:
            allowed = buf.getString().split(",");
            if (buf.getBoolean()) {
                if (changeRequested)
                    crh.notifySuccess();
                return Result.PARTIAL_SUCCESS;
            } else {
                if (changeRequested)
                    crh.notifyFailure();
                return Result.FAILURE;
            }
        case SSH_MSG_USERAUTH_PASSWD_CHANGEREQ:
            log.debug("Got x");
            if (changeRequested)
                crh = crh.notifyUnacceptable();
            if (crh != null) {
                crh.setPrompt(buf.getString());
                sendChangeReq(buf.getString());
                changeRequested = true;
                return Result.CONTINUED;
            } else
                return Result.FAILURE;
        default:
            log.error("Unexpected packet");
            return Result.FAILURE;
        }
    }
    
    private void sendChangeReq(String prompt) throws IOException
    {
        log.debug("Sending SSH_MSG_USERAUTH_PASSWD_CHANGEREQ");
        Buffer crbuf = session.createBuffer(Constants.Message.SSH_MSG_USERAUTH_PASSWD_CHANGEREQ);
        buildRequestCommon(crbuf);
        crbuf.putBoolean(true);
        crbuf.putString(pwdf.getPassword());
        crbuf.putString(crh.getNewPassword());
        session.writePacket(crbuf);
    }
    
}
