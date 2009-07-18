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
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.commons.net.ssh.AbstractService;
import org.apache.commons.net.ssh.SSHException;
import org.apache.commons.net.ssh.transport.Transport;
import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Event;
import org.apache.commons.net.ssh.util.LQString;
import org.apache.commons.net.ssh.util.Constants.DisconnectReason;
import org.apache.commons.net.ssh.util.Constants.Message;

/**
 * 
 * @author shikhar
 */
public class UserAuthProtocol extends AbstractService implements UserAuthService
{
    
    private final Iterator<AuthMethod> methods;
    
    private LQString banner; // auth banner
    
    private AuthMethod method; // currently active method
    
    private Set<String> allowed = new HashSet<String>();
    
    private final Deque<UserAuthException> savedEx = new ArrayDeque<UserAuthException>();
    
    private boolean partialSuccess;
    
    private volatile boolean requested;
    
    private final Event<UserAuthException> result = newEvent("userauth / got result");
    
    private final Lock lock = new ReentrantLock();
    
    private volatile boolean success;
    
    /**
     * Constructor that allows specifying an arbitary number of {@link AuthMethod}'s that will be
     * tried in order.
     * 
     * @param trans
     * @param methods
     */
    public UserAuthProtocol(Transport trans, AuthMethod... methods)
    {
        this(trans, Arrays.<AuthMethod> asList(methods));
    }
    
    /**
     * Constructor that allowos specifying an arbitary {@link Iterable} of {@link AuthMethod}'s that
     * will be tried in order.
     * 
     * @param trans
     * @param methods
     */
    public UserAuthProtocol(Transport trans, Iterable<AuthMethod> methods)
    {
        super(trans);
        this.methods = methods.iterator();
        for (AuthMethod m : methods) { // Initially assume at least first method allowed
            allowed.add(m.getName());
            break;
        }
    }
    
    // @return true = authenticated, false = only partially, more auth needed!
    public void authenticate() throws UserAuthException, TransportException
    {
        
        request(); // service request
        
        while (methods.hasNext()) {
            
            method = methods.next();
            
            log.info("Trying {} auth...", method.getName());
            if (!allowed.contains(method.getName()))
                continue;
            
            try {
                requested = true;
                method.request();
                result.await();
                if (success) {
                    // puts delayed compression into force if applicable
                    trans.setAuthenticated();
                    // we aren't in charge anymore, next service is
                    trans.setService(method.getNextService());
                    return;
                }
                requested = false;
            } catch (UserAuthException e) {
                // an exception requesting the method, let's give other methods a shot
                log.error("Saving for later - {}", e.toString());
                savedEx.push(e);
            }
            
            result.clear();
            
        }
        
        log.debug("Had {} saved exception(s)", savedEx.size());
        throw new UserAuthException("Exhausted availalbe authentication methods", savedEx.peek());
    }
    
    // Documented in interface
    public LQString getBanner()
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
    public boolean hadPartialSuccess()
    {
        return partialSuccess;
    }
    
    public void handle(Message cmd, Buffer buf) throws UserAuthException, TransportException
    {
        int num = cmd.toInt();
        if (num < 51 || num > 79)
            throw new TransportException(DisconnectReason.PROTOCOL_ERROR);
        
        if (cmd == Message.USERAUTH_BANNER) {
            
            banner = buf.getLQString();
            log.info("Auth banner - lang=[{}], text=[{}]", banner.getLanguage(), banner.getText());
            
        } else {
            
            lock.lock();
            try {
                
                if (requested) {
                    
                    if (cmd == Message.USERAUTH_FAILURE) {
                        
                        allowed = new HashSet<String>(Arrays.asList(buf.getString().split(",")));
                        partialSuccess |= buf.getBoolean();
                        if (!allowed.contains(method.getName()) || !method.retry())
                            result.error(method.getName() + " authentication failed");
                        
                    } else if (cmd == Message.USERAUTH_SUCCESS) {
                        
                        success = true;
                        result.set();
                        
                    } else {
                        
                        log.debug("Asking {} method to handle", method.getName());
                        if (!method.handle(cmd, buf))
                            // It did not recognize the message
                            result.error("Unknown packet received during " + method.getName() + " auth: " + cmd);
                    }
                    
                }

                else
                    
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
            if (requested)
                result.error(exception);
        } finally {
            lock.unlock();
        }
    }
    
    private Event<UserAuthException> newEvent(String name)
    {
        return new Event<UserAuthException>(name, UserAuthException.chainer, lock);
    }
    
}
