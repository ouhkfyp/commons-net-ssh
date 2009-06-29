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
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.commons.net.ssh.SSHException;
import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.transport.Session;
import org.apache.commons.net.ssh.userauth.AuthMethod.Result;
import org.apache.commons.net.ssh.userauth.AuthPassword.ChangeRequestHandler;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.LanguageQualifiedString;
import org.apache.commons.net.ssh.util.Constants.Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UserAuth implements UserAuthService
{
    public static class Builder implements UserAuthService.Builder
    {
        private final Session session;
        private final LinkedList<AuthMethod> methods = new LinkedList<AuthMethod>();
        private String username;
        private Service nextService;
        
        public Builder(Session session, String username, Service nextService)
        {
            this.session = session;
            this.username = username;
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
        
        public Builder authPublickey(KeyPair kp)
        {
            methods.add(new AuthPublickey(session, nextService, username, kp));
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
    
    protected final Session session;
    
    protected Set<String> allowed = new LinkedHashSet<String>();
    
    protected Queue<AuthMethod> methods;
    
    protected LanguageQualifiedString banner; // auth banner
    
    protected AuthMethod method; // currently active method
    protected AuthMethod.Result res; // its result
    protected ReentrantLock resLock = new ReentrantLock(); // lock for res
    protected Condition resCond = resLock.newCondition(); // signifies a conclusive resukt
    
    protected volatile Thread currentThread;
    protected volatile Exception exception;
    
    protected boolean active;
    
    private UserAuth(Session session, Queue<AuthMethod> methods)
    {
        this.session = session;
        this.methods = methods;
        for (AuthMethod m : methods)
            // initially assume all available are allowed
            allowed.add(m.getName());
    }
    
    public void authenticate() throws IOException
    {
        request();
        currentThread = Thread.currentThread();
        while (true) {
            if ((method = methods.poll()) == null)
                throw new SSHException("Exhausted available authentication methods");
            String name = method.getName();
            log.debug("Trying [{}] auth, allowed={}", name, allowed);
            if (!("composite@apache.org".equals(name) || allowed.contains(name)))
                continue;
            resLock.lock();
            try {
                res = Result.CONTINUED;
                method.request();
                while (res == Result.CONTINUED)
                    resCond.await();
                switch (res)
                {
                case SUCCESS:
                    return;
                case FAILURE:
                case PARTIAL_SUCCESS:
                    continue;
                default:
                    assert false;
                }
            } catch (InterruptedException e) {
                if (exception != null)
                    SSHException.chain(exception);
                else
                    throw new SSHException(e);
            } finally {
                resLock.unlock();
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
    
    public void handle(Message cmd, Buffer buf) throws IOException
    {
        switch (cmd)
        {
        case SSH_MSG_USERAUTH_BANNER:
            banner = buf.getLanguageQualifiedField();
            break;
        default:
            resLock.lock();
            try {
                switch (res = method.handle(cmd, buf))
                {
                case SUCCESS:
                    session.setAuthenticated();
                    session.setService(method.getNextService());
                    resCond.signal();
                    break;
                case FAILURE:
                    allowed = method.getAllowedMethods();
                    assert allowed != null;
                    resCond.signal();
                    break;
                case PARTIAL_SUCCESS:
                    log.info("partial success");
                    resCond.signal();
                    break;
                case CONTINUED:
                    break;
                default:
                    assert false;
                }
            } finally {
                resLock.unlock();
            }
        }
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
        resLock.lock();
        try {
            if (resLock.hasWaiters(resCond)) {
                assert currentThread != null;
                log.debug("interrupting {}", currentThread);
                currentThread.interrupt();
            }
        } finally {
            resLock.unlock();
        }
    }
    
}
