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

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.commons.net.ssh.AbstractService;
import org.apache.commons.net.ssh.SSHException;
import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.transport.Transport;
import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Event;
import org.apache.commons.net.ssh.util.Constants.DisconnectReason;
import org.apache.commons.net.ssh.util.Constants.Message;

/**
 * 
 * @author shikhar
 */
public class UserAuthProtocol extends AbstractService implements UserAuthService, AuthParams
{
    
    protected final ReentrantLock lock = new ReentrantLock();
    protected final Event<UserAuthException> result =
            new Event<UserAuthException>("userauth result", UserAuthException.chainer, lock);
    
    protected final Deque<UserAuthException> savedEx = new ArrayDeque<UserAuthException>();
    protected final Set<String> allowed = new HashSet<String>();
    
    protected AuthMethod method; // currently active method
    protected String banner; // auth banner
    
    protected boolean partialSuccess;
    
    protected String username;
    protected Service nextService;
    
    public UserAuthProtocol(Transport trans)
    {
        super(trans);
    }
    
    public synchronized void authenticate(String username, Service nextService, Iterable<AuthMethod> methods)
            throws UserAuthException, TransportException
    {
        this.username = username;
        this.nextService = nextService;
        
        for (AuthMethod meth : methods)
            // initially all methods allowed
            allowed.add(meth.getName());
        
        request(); // request "ssh-userauth" service
        
        for (AuthMethod meth : methods) {
            
            log.info("Trying {} auth...", meth.getName());
            if (!allowed.contains(meth.getName()))
                continue;
            
            lock.lock();
            try {
                this.method = meth;
                meth.init(this);
                result.clear();
                meth.request();
                if (result.get(trans.getConfig().getTimeout())) { // success
                    // puts delayed compression into force if applicable
                    trans.setAuthenticated();
                    // we aren't in charge anymore, next service is
                    trans.setService(nextService);
                    return;
                }
            } catch (UserAuthException e) {
                // an exception requesting the method, let's give other methods a shot
                log.error("Saving for later - {}", e.toString());
                savedEx.push(e);
            } finally {
                lock.unlock();
            }
        }
        
        log.debug("Had {} saved exception(s)", savedEx.size());
        throw new UserAuthException("Exhausted availalbe authentication methods", savedEx.peek());
    }
    
    public String getBanner()
    {
        return banner;
    }
    
    public String getName()
    {
        return NAME;
    }
    
    public String getNextServiceName()
    {
        return nextService.getName();
    }
    
    /**
     * Returns the exceptions that occured during authentication process but were ignored because
     * more methods were available for trying.
     * 
     * @return deque of saved exceptions
     */
    public Deque<UserAuthException> getSavedExceptions()
    {
        return savedEx;
    }
    
    public String getUsername()
    {
        return username;
    }
    
    public boolean hadPartialSuccess()
    {
        return partialSuccess;
    }
    
    public void handle(Message cmd, Buffer buf) throws UserAuthException, TransportException
    {
        if (cmd.toInt() < 51 || cmd.toInt() > 79)
            throw new TransportException(DisconnectReason.PROTOCOL_ERROR);
        
        lock.lock();
        try {
            if (cmd == Message.USERAUTH_BANNER)
                banner = buf.getString();
            else if (result.hasWaiters()) { // i.e. made an auth req & waiting for result 
                if (cmd == Message.USERAUTH_FAILURE) {
                    allowed.clear();
                    allowed.addAll(Arrays.<String> asList(buf.getString().split(",")));
                    partialSuccess |= buf.getBoolean();
                    if (allowed.contains(method.getName()) && method.shouldRetry())
                        method.request();
                    else
                        result.set(false);
                } else if (cmd == Message.USERAUTH_SUCCESS)
                    result.set(true);
                else {
                    log.debug("Asking {} method to handle", method.getName());
                    method.handle(cmd, buf);
                }
            } else
                trans.sendUnimplemented();
        } finally {
            lock.unlock();
        }
    }
    
    public void notifyError(SSHException exception)
    {
        lock.lock();
        try {
            if (result.hasWaiters())
                result.error(exception);
        } finally {
            lock.unlock();
        }
    }
    
}
