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

import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.transport.Transport;
import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Constants.Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This abstract class for {@link AuthMethod} implements common or default functionality.
 * 
 * @author shikhar
 */
public abstract class AbstractAuthMethod implements AuthMethod
{
    
    protected final Logger log = LoggerFactory.getLogger(getClass());
    
    /** Transport layer */
    protected final Transport trans;
    
    /** The next service we want to start on successful authentication */
    protected final Service nextService;
    
    /** Username for the account we are trying to authenticate */
    protected final String username;
    
    /** Allowed methods (may be {@code null} in case we haven't got an opportunity to set it) */
    protected String allowed;
    
    /**
     * Constructor
     * 
     * @param trans
     *            transport layer
     * @param nextService
     *            service to start on successful authentication
     * @param username
     *            username for this authentication attempt
     */
    protected AbstractAuthMethod(Transport trans, Service nextService, String username)
    {
        assert trans != null && nextService != null && username != null;
        this.trans = trans;
        this.nextService = nextService;
        this.username = username;
    }
    
    // Documented in interface
    public String getAllowed()
    {
        return allowed;
    }
    
    // Documented in AuthMethod
    public Service getNextService()
    {
        return nextService;
    }
    
    // Documented in interface
    public String getUsername()
    {
        return username;
    }
    
    public boolean handle(Message cmd, Buffer buf) throws UserAuthException, TransportException
    {
        return false;
    }
    
    /**
     * Simply constructs a request packet with {@link #buildReq()} and writes it to the
     * {@link #trans}.
     * <p>
     * Subclasses should thus either override this method or {@link #buildReq()}.
     */
    public void request() throws UserAuthException, TransportException
    {
        log.debug("Sending SSH_MSG_USERAUTH_REQUEST for {}", username);
        trans.writePacket(buildReq());
    }
    
    public boolean retry() throws TransportException, UserAuthException
    {
        return false;
    }
    
    /**
     * Make a SSH_MSG_USERAUTH_REQUEST packet replete with the generic fields common to all methods
     * i.e. the username, next service name, and method name.
     * <p>
     * Subclasses may then add the fields that are specific to them.
     * 
     * @return {@link Buffer} containing the packet
     */
    protected Buffer buildReq() throws UserAuthException
    {
        return new Buffer(Message.USERAUTH_REQUEST) // SSH_MSG_USERAUTH_REQUEST
                                                   .putString(username) // username goes first
                                                   .putString(nextService.getName()) // the service that we'd like on success
                                                   .putString(getName()); // name of auth method
    }
    
}
