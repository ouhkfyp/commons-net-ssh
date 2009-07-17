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

import org.apache.commons.net.ssh.AbstractService;
import org.apache.commons.net.ssh.SSHException;
import org.apache.commons.net.ssh.SSHRuntimeException;
import org.apache.commons.net.ssh.transport.Transport;
import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.userauth.AuthMethod.Result;
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
    private AuthMethod.Result res; // its result
    
    private Set<String> allowed = new HashSet<String>();
    
    private final Deque<UserAuthException> savedEx = new ArrayDeque<UserAuthException>();
    
    private boolean partialSuccess;
    
    private final Event<UserAuthException> conclusiveResult =
            new Event<UserAuthException>("userauth / concusive result", UserAuthException.chainer);
    
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
        if (trans.getService() != null && trans.getService().getName() == NAME)
            throw new SSHRuntimeException("Concurrent authentication attempt not possible");
        
        request(); // service request
        
        while (methods.hasNext()) {
            
            method = methods.next();
            
            log.info("Trying {} auth...", method.getName());
            if (!allowed.contains(method.getName()))
                continue;
            
            try {
                method.request();
            } catch (UserAuthException e) {
                // an exception requesting the method, let's give other methods a shot
                log.error("Saving for later - {}", e.toString());
                savedEx.push(e);
                continue;
            }
            
            // wait until we have the result of this method
            conclusiveResult.await();
            
            switch (res)
            {
            case SUCCESS:
                return; // Exit point for successful auth
            case PARTIAL_SUCCESS:
                partialSuccess = true;
                continue;
            case FAILURE:
                savedEx.push(new UserAuthException(method.getName() + " authentication failed"));
                continue;
            default:
                assert false;
            }
            
            conclusiveResult.clear();
            
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
    
    public boolean hadPartialSuccess()
    {
        return partialSuccess;
    }
    
    // Documented in interface
    public void handle(Message cmd, Buffer buf) throws UserAuthException, TransportException
    {
        if (cmd.toInt() < 50 || cmd.toInt() > 79)
            throw new TransportException(DisconnectReason.PROTOCOL_ERROR);
        /*
         * Here we are being asked to handle a packet that is meant for the ssh-userauth service.
         * 
         * First we check if it is the banner, and if so store it. Otherwise, we find out from the
         * currently active authentication method what the packet implies - SUCCESS, FAILURE,
         * PARTIAL_SUCCESS, or that a conclusive result has not yet been reached (CONTINUED).
         * 
         * In all but the last case, we signal on resCond so that any thread waiting on the result
         * gets notified.
         */
        switch (cmd)
        {
        case USERAUTH_BANNER:
            banner = buf.getLQString();
            log.info("Auth banner - lang=[{}], text=[{}]", banner.getLanguage(), banner.getText());
            break;
        default:
            try {
                res = method.handle(cmd, buf);
                log.info("Auth result = {}", res);
                switch (res)
                {
                case SUCCESS:
                    trans.setAuthenticated(); // notify session so that delayed comression may become effective if applicable
                    trans.setService(method.getNextService()); // we aren't in charge anymore, next service is
                    conclusiveResult.set();
                    break;
                case FAILURE:
                    // the server would have told us which auth methods can continue now
                    allowed = new HashSet<String>(Arrays.asList(method.getAllowed().split(",")));
                    conclusiveResult.set();
                    break;
                case PARTIAL_SUCCESS:
                    conclusiveResult.set();
                    break;
                case CONTINUED:
                    // let resCond awaiter keep waiting, since the current method has not yet concluded
                    break;
                case UNKNOWN:
                    throw new UserAuthException("Could not decipher packet");
                default:
                    assert false;
                }
            } catch (UserAuthException e) {
                // UserAuthException when asking the method to tell us the result
                log.error("Saving for later - {}", e.toString());
                savedEx.push(e);
                res = Result.FAILURE;
                conclusiveResult.set();
            }
        }
    }
    
    public void notifyError(SSHException exception)
    {
        conclusiveResult.error(exception);
    }
    
    // Documented in interface
    public void notifyUnimplemented(int seqNum) throws SSHException
    {
        throw new UserAuthException("Unexpected: SSH_MSG_UNIMPLEMENTED");
    }
    
}
