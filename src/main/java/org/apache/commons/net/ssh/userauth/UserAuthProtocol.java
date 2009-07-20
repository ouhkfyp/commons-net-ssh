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
import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Event;
import org.apache.commons.net.ssh.util.Constants.DisconnectReason;
import org.apache.commons.net.ssh.util.Constants.Message;

/**
 * 
 * @author shikhar
 */
public class UserAuthProtocol extends AbstractService implements UserAuthService
{
    
    private static final int TIMEOUT = 60;
    
    private final AuthParams params;
    
    private final ReentrantLock lock = new ReentrantLock();
    private final Event<UserAuthException> result =
            new Event<UserAuthException>("userauth result", UserAuthException.chainer, lock);
    private final Deque<UserAuthException> savedEx = new ArrayDeque<UserAuthException>();
    private final Set<String> allowed = new HashSet<String>();
    
    private AuthMethod method; // currently active method
    private String banner; // auth banner
    
    private boolean partialSuccess;
    
    public UserAuthProtocol(AuthParams params)
    {
        super(params.getTransport());
        this.params = params;
    }
    
    public synchronized void authenticate(AuthMethod... methods) throws UserAuthException, TransportException
    {
        authenticate(Arrays.<AuthMethod> asList(methods));
    }
    
    public synchronized void authenticate(Iterable<AuthMethod> methods) throws UserAuthException, TransportException
    {
        // initially all methods allowed
        for (AuthMethod meth : methods)
            allowed.add(meth.getName());
        // service request
        request();
        
        for (AuthMethod meth : methods) {
            
            log.info("Trying {} auth...", meth.getName());
            if (!allowed.contains(meth.getName()))
                continue;
            
            lock.lock();
            try {
                this.method = meth;
                meth.init(params);
                result.clear();
                meth.request();
                if (result.get(TIMEOUT)) { // success
                    // puts delayed compression into force if applicable
                    trans.setAuthenticated();
                    // we aren't in charge anymore, next service is
                    trans.setService(params.getNextService());
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
    
    // Documented in interface
    public synchronized String getBanner()
    {
        return banner;
    }
    
    // Documented in interface
    public String getName()
    {
        return NAME;
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
    
    // Documented in interface
    public synchronized boolean hadPartialSuccess()
    {
        return partialSuccess;
    }
    
    public void handle(Message cmd, Buffer buf) throws UserAuthException, TransportException
    {
        if (cmd.toInt() < 51 || cmd.toInt() > 79)
            throw new TransportException(DisconnectReason.PROTOCOL_ERROR);
        
        if (cmd == Message.USERAUTH_BANNER)
            banner = buf.getString();
        else {
            lock.lock();
            try {
                if (result.hasWaiters()) {
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
