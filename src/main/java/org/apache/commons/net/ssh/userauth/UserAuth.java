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
import java.util.LinkedList;
import java.util.Queue;
import java.util.concurrent.Semaphore;

import org.apache.commons.net.ssh.SSHException;
import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.transport.Session;
import org.apache.commons.net.ssh.userauth.AuthPassword.ChangeRequestHandler;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Constants;
import org.apache.commons.net.ssh.util.LanguageQualifiedString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UserAuth implements UserAuthService
{
    public static class Builder implements UserAuthService.Builder
    {
        private final Session session;
        private final LinkedList<AuthMethod> methods = new LinkedList<AuthMethod>();
        private String username = System.getProperty("user.name");
        private Service nextService;
        
        public Builder(Session session, Service nextService)
        {
            this.session = session;
            this.nextService = nextService;
        }
        
        public Builder authMethod(AuthMethod method)
        {
            methods.add(method);
            return this;
        }
        
        public Builder authPassword(PasswordFinder pwdf)
        {
            return authPassword(pwdf, null);
        }
        
        public Builder authPassword(PasswordFinder pwdf, ChangeRequestHandler crh)
        {
            methods.add(new AuthPassword(session, nextService, username, pwdf, crh));
            return this;
        }
        
        public UserAuthService build()
        {
            return new UserAuth(session, methods);
        }
        
        public Builder withNextService(Service nextService)
        {
            this.nextService = nextService;
            return this;
        }
        
        public Builder withUsername(String username)
        {
            this.username = username;
            return this;
        }
        
    }
    
    protected final Logger log = LoggerFactory.getLogger(getClass());
    
    protected String[] allowedMeths = { "password" };
    
    protected Queue<AuthMethod> methods;
    
    protected final Session session;
    
    protected LanguageQualifiedString banner;
    
    protected AuthMethod activeMeth; // currently active method
    
    protected final Semaphore sema = new Semaphore(0);
    
    protected Thread currentThread;
    
    protected AuthMethod.Result lastRes;
    
    protected Exception exception;
    
    protected boolean active;
    
    private UserAuth(Session session, Queue<AuthMethod> methods)
    {
        this.session = session;
        this.methods = methods;
    }
    
    public void authenticate() throws IOException
    {
        if (methods == null)
            throw new SSHException("No authentication methods provided");
        request();
        while (true) {
            if ((activeMeth = methods.poll()) == null)
                throw new SSHException("Exhausted available authentication methods");
            if (!isAllowed(activeMeth.getName()))
                continue;
            try {
                activeMeth.request();
                currentThread = Thread.currentThread();
                sema.acquire();
            } catch (Exception e) {
                SSHException.chain(exception);
            }
            switch (lastRes)
            {
            case SUCCESS:
                session.setService(activeMeth.getNextService());
                return;
            case FAILURE:
            case PARTIAL_SUCCESS:
                continue;
            }
        }
    }
    
    public LanguageQualifiedString getBanner()
    {
        return banner;
    }
    
    public String getName()
    {
        return NAME;
    }
    
    public Session getSession()
    {
        return session;
    }
    
    public void handle(Constants.Message cmd, Buffer buf) throws IOException
    {
        switch (cmd)
        {
        case SSH_MSG_USERAUTH_BANNER:
            banner = buf.getLanguageQualifiedField();
            break;
        default:
            lastRes = activeMeth.handle(cmd, buf);
            log.debug("Result of {} auth: {}", activeMeth.getName(), lastRes);
            switch (lastRes)
            {
            case SUCCESS:
                session.setAuthenticated();
                sema.release();
                break;
            case FAILURE:
                allowedMeths = activeMeth.getAllowedMethods();
                log.info("Allowed methods: {}", allowedMeths);
                sema.release();
                break;
            case PARTIAL_SUCCESS:
                log.info("partial success");
                sema.release();
                break;
            case CONTINUED:
                break;
            default:
                assert false;
            }
        }
    }
    
    protected boolean isAllowed(String methodName)
    {
        if ("composite@apache.org".equals(methodName))
            return true;
        for (String x : allowedMeths)
            if (x.equals(methodName))
                return true;
        return false;
    }
    
    public void request() throws IOException
    {
        try {
            if (!equals(session.getActiveService()))
                session.reqService(this);
        } catch (Exception e) {
            throw new IOException(e);
        }
    }
    
    public void setError(Exception ex)
    {
        exception = ex;
        if (currentThread != null)
            currentThread.interrupt();
    }
}
