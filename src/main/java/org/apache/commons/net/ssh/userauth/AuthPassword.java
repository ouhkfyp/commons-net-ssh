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

import org.apache.commons.net.ssh.PasswordFinder;
import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.Constants.Message;
import org.apache.commons.net.ssh.PasswordFinder.Resource;
import org.apache.commons.net.ssh.transport.Session;
import org.apache.commons.net.ssh.util.Buffer;

public class AuthPassword extends AbstractAuthMethod
{
    
    public static final String NAME = "password";
    
    private final PasswordFinder pwdf;
    private final Resource resource;
    
    public AuthPassword(Session session, Service nextService, String username, PasswordFinder pwdf)
    {
        super(session, nextService, username);
        assert pwdf != null;
        this.pwdf = pwdf;
        resource = new Resource(Resource.Type.ACCOUNT, username);
    }
    
    @Override
    protected Buffer buildRequest()
    {
        Buffer buf = buildRequestCommon(new Buffer(Message.USERAUTH_REQUEST));
        buf.putBoolean(false);
        buf.putPassword(pwdf.getPassword(resource));
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
            else if (allowed.contains(NAME) && pwdf.retry()) {
                request();
                return Result.CONTINUED;
            } else
                return Result.FAILURE;
        case USERAUTH_60: // SSH_MSG_USERAUTH_PASSWD_CHANGEREQ
            log.info("Password change request received, ignoring");
            return Result.FAILURE; // throw an exception here instead??
        default:
            return Result.UNKNOWN;
        }
    }
    
}

// COMMENTED out bellow (password change handling as part of the password auth method) because
// introduced complexity without any proof of real world usage, kinda impossible to test :-)

// public interface ChangeRequestHandler extends PasswordFinder
// {
// char[] getNewPassword(Resource resource, String info);
//    
// void notifyFailure();
//    
// void notifySuccess();
//    
// ChangeRequestHandler notifyUnacceptable();
//    
// void setPrompt(LQString prompt);
// }
// private void sendChangeReq(String prompt) throws IOException
// {
// Buffer buf = buildRequestCommon(new Buffer(Message.USERAUTH_60));
// buf.putBoolean(true);
// buf.putString(crh.getPassword(Resource.USER, username));
// buf.putString(crh.getNewPassword(Resource.USER, username));
// log.debug("Sending SSH_MSG_USERAUTH_PASSWD_CHANGEREQ");
// session.writePacket(buf);
// }
