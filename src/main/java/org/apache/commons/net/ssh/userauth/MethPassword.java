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

public class MethPassword implements Method
{
    
    public interface ChangeRequestHandler
    {
        char[] getNewPassword();
        
        void notifyFailure();
        
        void notifySuccess();
        
        ChangeRequestHandler notifyUnacceptable();
        
        void setPrompt(String prompt);
    }
    
    public static final String NAME = "password";
    
    private final Session session;
    private final String username;
    private final String nextService;
    private final PasswordFinder pwdf;
    
    private String[] allowed;
    private ChangeRequestHandler crh;
    private boolean changeRequested = false;
    
    public MethPassword(Session session, String username, String nextService, PasswordFinder pwdf)
    {
        this.session = session;
        this.username = username;
        this.nextService = nextService;
        this.pwdf = pwdf;
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
            if (changeRequested)
                crh = crh.notifyUnacceptable();
            if (crh != null) {
                crh.setPrompt(buf.getString());
                sendChangeReq(buf.getString());
                changeRequested = true;
            }
            return Result.CONTINUED;
        }
        return null;
    }
    
    private void sendChangeReq(String prompt) throws IOException
    {
        Buffer crbuf = session.createBuffer(Constants.Message.SSH_MSG_USERAUTH_PASSWD_CHANGEREQ);
        buildRequestCommon(crbuf);
        crbuf.putBoolean(true);
        crbuf.putString(pwdf.getPassword());
        crbuf.putString(crh.getNewPassword());
        session.writePacket(crbuf);
    }
    
    public void setChangeRequestHandler(ChangeRequestHandler crh)
    {
        this.crh = crh;
    }
    
}
