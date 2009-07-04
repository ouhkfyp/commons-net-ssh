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

import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.commons.net.ssh.AbstractService;
import org.apache.commons.net.ssh.Session;
import org.apache.commons.net.ssh.Constants.Message;
import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.userauth.AuthMethod.Result;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.LQString;

public class UserAuthProtocol extends AbstractService implements UserAuthService
{
    
    private final Queue<AuthMethod> methods;
    
    private LQString banner; // auth banner
    
    private AuthMethod method; // currently active method
    private AuthMethod.Result res; // its result
    private final ReentrantLock resLock = new ReentrantLock(); // lock for res
    private final Condition resCond = resLock.newCondition(); // signifies a conclusive result
    
    private Set<String> allowed = new HashSet<String>();
    
    public UserAuthProtocol(Session session, Collection<AuthMethod> methods)
    {
        super(session);
        this.methods = new LinkedList<AuthMethod>(methods);
        for (AuthMethod m : methods)
            // initially assume all are allowed
            allowed.add(m.getName());
    }
    
    // @return true = authenticated, false = only partially, more auth needed!
    public boolean authenticate() throws UserAuthException
    {
        boolean partialSuccess = false;
        try { // service request
            request();
        } catch (TransportException e) {
            throw new UserAuthException(e);
        }
        enterInterruptibleContext();
        for (;;) {
            if ((method = methods.poll()) == null)
                if (partialSuccess)
                    return false;
                else
                    throw new UserAuthException("Exhausted available authentication methods");
            log.info("Trying {} auth...", method.getName());
            if (!allowed.contains(method.getName()))
                continue;
            resLock.lock();
            res = Result.CONTINUED;
            try {
                try {
                    method.request();
                } catch (Exception e) {
                    log.error("... but it spewed - {}", e.toString());
                    continue;
                }
                while (res == Result.CONTINUED)
                    resCond.await();
                switch (res)
                {
                case SUCCESS:
                    return true;
                case FAILURE:
                case PARTIAL_SUCCESS:
                    partialSuccess = true;
                    continue;
                default:
                    assert false;
                }
            } catch (InterruptedException e) {
                log.debug("Got interrupted");
                if (exception != null)
                    throw UserAuthException.chain(exception);
                else
                    throw new UserAuthException(e);
            } finally {
                leaveInterruptibleContext();
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
    
    @Override
    public Session getSession()
    {
        return session;
    }
    
    public void gotUnimplemented(int seqNum)
    {
        // TODO Auto-generated method stub
    }
    
    public void handle(Message cmd, Buffer buf) throws UserAuthException
    {
        switch (cmd)
        {
        case USERAUTH_BANNER:
            banner = buf.getLQString();
            log.info("Auth banner - lang=[{}], text=[{}]", banner.getLanguage(), banner.getText());
            break;
        default:
            resLock.lock();
            try {
                res = method.handle(cmd, buf);
                log.info("Auth result = {}", res);
                switch (res)
                {
                case SUCCESS:
                    session.setAuthenticated();
                    session.setService(method.getNextService());
                    resCond.signal();
                    break;
                case FAILURE:
                    allowed = method.getAllowedMethods();
                    resCond.signal();
                    break;
                case PARTIAL_SUCCESS:
                    resCond.signal();
                    break;
                case CONTINUED:
                    break;
                default:
                    assert false;
                }
            } catch (Exception e) {
                log.error("{} method spewed - {}", method.getName(), e.toString());
                res = Result.FAILURE;
                resCond.signal();
            } finally {
                resLock.unlock();
            }
        }
    }
    
    @Override
    protected boolean shouldInterrupt()
    {
        resLock.lock();
        try {
            return resLock.hasWaiters(resCond);
        } finally {
            resLock.unlock();
        }
    }
    
}
