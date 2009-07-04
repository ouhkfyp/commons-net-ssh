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

import org.apache.commons.net.ssh.PasswordFinder;
import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.Session;
import org.apache.commons.net.ssh.Constants.Message;
import org.apache.commons.net.ssh.PasswordFinder.Resource;
import org.apache.commons.net.ssh.transport.TransportException;
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
    
    public String getName()
    {
        return NAME;
    }
    
    @Override
    public Result handle(Message cmd, Buffer buf) throws UserAuthException, TransportException
    {
        Result res = super.handle(cmd, buf);
        switch (res)
        {
        case FAILURE:
            if (allowed.contains(NAME) && pwdf.retry()) {
                request();
                return Result.CONTINUED;
            }
            break;
        case UNKNOWN:
            if (cmd == Message.USERAUTH_60) {
                log.error("Received SSH_MSG_USERAUTH_CHANGERQ; password needs changing");
                return Result.FAILURE;
            }
            break;
        }
        return res;
    }
    
    @Override
    protected Buffer buildReq()
    {
        return buildReqCommon() // the generic stuff
                .putBoolean(false) // no, we are not responding to a CHANGEREQ
                .putPassword(pwdf.getPassword(resource)); // putPassword blanks char[]
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
