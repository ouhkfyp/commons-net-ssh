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
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.commons.net.ssh.AbstractService;
import org.apache.commons.net.ssh.Session;
import org.apache.commons.net.ssh.TransportException;
import org.apache.commons.net.ssh.userauth.AuthMethod.Result;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.LQString;
import org.apache.commons.net.ssh.util.Constants.Message;

public class UserAuthProtocol extends AbstractService implements UserAuthService
{
    
    private final Iterator<AuthMethod> methods;
    
    private LQString banner; // auth banner
    
    private AuthMethod method; // currently active method
    private AuthMethod.Result res; // its result
    private final ReentrantLock resLock = new ReentrantLock(); // lock for res
    private final Condition resCond = resLock.newCondition(); // signifies a conclusive result
    
    private Set<String> allowed = new HashSet<String>();
    
    private final Deque<UserAuthException> savedEx = new ArrayDeque<UserAuthException>();
    
    public UserAuthProtocol(Session session, AuthMethod... methods)
    {
        this(session, Arrays.<AuthMethod> asList(methods));
    }
    
    public UserAuthProtocol(Session session, Iterable<AuthMethod> methods)
    {
        super(session);
        this.methods = methods.iterator();
        for (AuthMethod m : methods)
            // initially assume all are allowed
            allowed.add(m.getName());
    }
    
    // @return true = authenticated, false = only partially, more auth needed!
    public boolean authenticate() throws UserAuthException, TransportException
    {
        
        boolean partialSuccess = false;
        
        request(); // service request
        
        while (methods.hasNext()) {
            
            method = methods.next();
            
            log.info("Trying {} auth...", method.getName());
            if (!allowed.contains(method.getName()))
                continue;
            
            try {
                method.request();
            } catch (UserAuthException e) {
                // some other exception with the method, let's give other methods a shot
                log.error("Saving for later - {}", e.toString());
                savedEx.push(e);
                continue;
            }
            
            resLock.lock();
            enterInterruptibleContext();
            try {
                for (res = Result.CONTINUED; res == Result.CONTINUED; resCond.await())
                    ;
            } catch (InterruptedException ie) {
                log.debug("Got interrupted");
                
                if (exception != null) // were interrupted by AbstractService#notifyError
                    if (exception instanceof TransportException)
                        throw (TransportException) exception;
                    else
                        throw UserAuthException.chain(exception);
                else
                    throw new UserAuthException(ie);
            } finally {
                resLock.unlock();
                leaveInterruptibleContext();
            }
            
            switch (res)
            {
            case SUCCESS:
                return true; // exit point for fully successful auth
            case PARTIAL_SUCCESS:
                partialSuccess = true;
                continue;
            case FAILURE:
                continue;
            default:
                assert false;
            }
            
        }
        
        if (partialSuccess)
            return false;
        
        else if (!savedEx.isEmpty()) {
            /*
             * it would be informative to throw the last exception thrown by an auth method
             * (especially when precisely one method had to be tried)
             */
            log.debug("Had {} saved exceptions", savedEx.size());
            throw UserAuthException.chain(savedEx.peek());
        }

        else
            throw new UserAuthException("Exhausted available authentication methods");
        
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
    
    public void handle(Message cmd, Buffer buf) throws UserAuthException, TransportException
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
                case UNKNOWN:
                    throw new UserAuthException("Could not decipher packet");
                default:
                    assert false;
                }
            } catch (UserAuthException e) {
                log.error("Saving for later - {}", e.toString());
                savedEx.push(e);
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
