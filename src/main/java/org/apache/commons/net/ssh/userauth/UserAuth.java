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
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.commons.net.ssh.SSHException;
import org.apache.commons.net.ssh.Constants.Message;
import org.apache.commons.net.ssh.transport.Session;
import org.apache.commons.net.ssh.userauth.AuthMethod.Result;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.LQString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UserAuth implements UserAuthService
{
    
    protected final Logger log = LoggerFactory.getLogger(getClass());
    
    protected final Session session;
    
    protected Set<String> allowed = new LinkedHashSet<String>();
    
    protected Queue<AuthMethod> methods;
    
    protected LQString banner; // auth banner
    
    protected AuthMethod method; // currently active method
    protected AuthMethod.Result res; // its result
    protected ReentrantLock resLock = new ReentrantLock(); // lock for res
    protected Condition resCond = resLock.newCondition(); // signifies a conclusive resukt
    
    protected volatile Thread currentThread;
    protected volatile SSHException exception;
    
    protected boolean active;
    
    UserAuth(Session session, Queue<AuthMethod> methods)
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
            res = Result.CONTINUED;
            try {
                try {
                    method.request();
                } catch (Exception e) {
                    continue;
                }
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
                    throw exception;
                else
                    throw new SSHException(e);
            } finally {
                resLock.unlock();
            }
        }
    }
    
    public LQString getBanner()
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
        case USERAUTH_BANNER:
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
                    allowed = new LinkedHashSet<String>(Arrays.asList(method.getAllowedMethods()));
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
            } catch (Exception e) {
                log.error("{} auth encountered error: {}", method.getName(), e.toString());
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
    
    public void setError(SSHException ex)
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
