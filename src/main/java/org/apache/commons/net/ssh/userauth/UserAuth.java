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
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.commons.net.ssh.Constants;
import org.apache.commons.net.ssh.SSHException;
import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.transport.Session;
import org.apache.commons.net.ssh.userauth.MethPassword.ChangeRequestHandler;
import org.apache.commons.net.ssh.util.Buffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UserAuth implements Service
{
    
    public static class Builder
    {
        private final Session session;
        private final Queue<Method> methods = new LinkedList<Method>();
        private final String username;
        private String nextService = Constants.SERVICE_CONN;
        
        public Builder(Session session, String username)
        {
            this.session = session;
            this.username = username;
        }
        
        public UserAuth build()
        {
            return new UserAuth(this);
        }
        
        public Builder hostbased(KeyPair hostKey)
        {
            return this;
        }
        
        public Builder nextService(String nextService)
        {
            this.nextService = nextService;
            return this;
        }
        
        public Builder password(PasswordFinder pwdf)
        {
            return password(pwdf, null);
        }
        
        public Builder password(PasswordFinder pwdf, ChangeRequestHandler crh)
        {
            methods.add(new MethPassword(session, username, nextService, pwdf, crh));
            return this;
        }
        
        public Builder publickey(KeyPair ident)
        {
            methods.add(new MethPublickey(session, username, nextService, ident));
            return this;
        }
        
        public Builder publickey(KeyPair[] idents)
        {
            for (KeyPair ident : idents)
                publickey(ident);
            return this;
        }
        
        public Builder publickey(List<KeyPair> idents)
        {
            return this;
        }
        
    }
    
    private final Logger log = LoggerFactory.getLogger(getClass());
    
    private final List<String> allowedMethods = Arrays.asList("publickey", "password");
    
    private final Queue<Method> methods;
    
    private final Session session;
    
    private String nextService = Constants.SERVICE_CONN; // default
    
    private String banner;
    
    private Method activeMethod; // currently active method
    
    private final ReentrantLock authLock = new ReentrantLock();
    private final Condition methodComplete = authLock.newCondition();
    
    public static final String NAME = "ssh-userauth";
    
    public UserAuth(Builder builder)
    {
        this.session = builder.session;
        this.nextService = builder.nextService;
        this.methods = builder.methods;
    }
    
    public void authenticate() throws SSHException
    {
        
    }
    
    public String getBanner()
    {
        return banner;
    }
    
    public String getName()
    {
        return NAME;
    }
    
    public void handle(Constants.Message cmd, Buffer packet) throws Exception
    {
        switch (cmd)
        {
        case SSH_MSG_USERAUTH_BANNER:
            banner = packet.getString();
            break;
        default:
            switch (activeMethod.next(cmd, packet))
            {
            case SUCCESS:
                log.info("success");
                session.setAuthenticated();
                break;
            case FAILURE:
                log.info("failure, allowed = {}", allowedMethods.toString());
                break;
            case PARTIAL_SUCCESS:
                log.info("partial success");
                break;
            case CONTINUED:
                break;
            default:
                assert false;
            }
        }
    }
    
    protected void request() throws IOException
    {
        assert allowedMethods.contains(activeMethod.getName());
        Buffer buffer = session.createBuffer(Constants.Message.SSH_MSG_USERAUTH_REQUEST);
        activeMethod.buildRequest(buffer);
        session.writePacket(buffer);
    }
    
    public void setError(Exception ex)
    {
        
    }
    
}
