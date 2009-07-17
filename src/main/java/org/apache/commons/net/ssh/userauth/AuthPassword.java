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
import org.apache.commons.net.ssh.PasswordFinder.Resource;
import org.apache.commons.net.ssh.transport.Transport;
import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Constants.Message;

public class AuthPassword extends AbstractAuthMethod
{
    
    public static final String NAME = "password";
    
    private final PasswordFinder pwdf;
    private final Resource resource;
    
    public AuthPassword(Transport trans, Service nextService, String username, PasswordFinder pwdf)
    {
        super(trans, nextService, username);
        assert pwdf != null;
        this.pwdf = pwdf;
        resource = new Resource(Resource.Type.ACCOUNT, username + "@" + trans.getRemoteHost().getHostName());
    }
    
    public String getName()
    {
        return NAME;
    }
    
    @Override
    public Result handle(Message cmd, Buffer buf) throws UserAuthException, TransportException
    {
        Result res = super.handle(cmd, buf);
        switch (cmd)
        {
        case USERAUTH_FAILURE:
            if (allowed.contains(NAME) && pwdf.retry(resource)) {
                request();
                return Result.CONTINUED;
            }
            break;
        case USERAUTH_60:
            log.error("Received SSH_MSG_USERAUTH_CHANGERQ; password needs changing");
            return Result.FAILURE;
        }
        return res;
    }
    
    @Override
    protected Buffer buildReq() throws UserAuthException
    {
        log.info("Requesting password for " + resource);
        char[] password = pwdf.reqPassword(resource);
        try {
            if (password == null)
                throw new UserAuthException("Was given null password for " + resource);
            else
                return super.buildReq() // the generic stuff
                            .putBoolean(false) // no, we are not responding to a CHANGEREQ
                            .putPassword(password);
        } finally {
            password = null;
        }
    }
    
}
