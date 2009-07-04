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

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.Session;
import org.apache.commons.net.ssh.Constants.Message;
import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.util.Buffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractAuthMethod implements AuthMethod
{
    
    protected final Logger log = LoggerFactory.getLogger(getClass());
    
    /** Transport layer */
    protected final Session session;
    
    /** The next service we want to start on successful auth */
    protected final Service nextService;
    
    /** Username for the account we are trying to authenticate */
    protected final String username;
    
    /** Allowed methods (may be {@code null} in case we haven't got an opportunity to set it) */
    protected volatile Set<String> allowed;
    
    /**
     * @param session
     *            transport layer
     * @param nextService
     *            service to start on successful auth
     * @param username
     *            username for this authentication attempt
     */
    public AbstractAuthMethod(Session session, Service nextService, String username)
    {
        assert session != null && nextService != null && username != null;
        this.session = session;
        this.nextService = nextService;
        this.username = username;
    }
    
    /*
     * (non-Javadoc)
     * 
     * @see org.apache.commons.net.ssh.userauth.AuthMethod#getAllowedMethods()
     */
    public Set<String> getAllowedMethods()
    {
        return allowed;
    }
    
    /*
     * (non-Javadoc)
     * 
     * @see org.apache.commons.net.ssh.userauth.AuthMethod#getNextService()
     */
    public Service getNextService()
    {
        return nextService;
    }
    
    /*
     * (non-Javadoc)
     * 
     * @see org.apache.commons.net.ssh.userauth.AuthMethod#getUsername()
     */
    public String getUsername()
    {
        return username;
    }
    
    /*
     * (non-Javadoc)
     * 
     * @see
     * org.apache.commons.net.ssh.userauth.AuthMethod#handle(org.apache.commons.net.ssh.Constants
     * .Message, org.apache.commons.net.ssh.util.Buffer)
     */
    public Result handle(Message cmd, Buffer buf) throws UserAuthException, TransportException
    {
        switch (cmd)
        {
        case USERAUTH_SUCCESS:
            return Result.SUCCESS;
        case USERAUTH_FAILURE:
            setAllowedMethods(buf.getString());
            return buf.getBoolean() ? Result.PARTIAL_SUCCESS : Result.FAILURE;
        default:
            return Result.UNKNOWN;
        }
    }
    
    /*
     * (non-Javadoc)
     * 
     * @see org.apache.commons.net.ssh.userauth.AuthMethod#request()
     */
    public void request() throws UserAuthException, TransportException
    {
        log.debug("Sending SSH_MSG_USERAUTH_REQUEST for {}", username);
        session.writePacket(buildReq());
    }
    
    /**
     * Make the SSH_MSG_USERAUTH_REQUEST packet
     * 
     * @return the {@link Buffer} containing constructed request
     */
    abstract protected Buffer buildReq() throws UserAuthException;
    
    /**
     * Make a SSH_MSG_USERAUTH_REQUEST packet replete with the generic fields common to all methods
     * 
     * @return {@link Buffer} containing the packet
     */
    protected Buffer buildReqCommon()
    {
        return new Buffer(Message.USERAUTH_REQUEST) // SSH_MSG_USERAUTH_REQUEST
                .putString(username) // username goes first
                .putString(nextService.getName()) // the service that we'd like on success
                .putString(getName()); // name of auth method
    }
    
    /**
     * Take the comma-delimted string containing allowed methods as indicated by the server, make a
     * {@code Set<String>} out of them and set the {@link allowed} field with that.
     * 
     * @param commaDelimed
     *            the pertinent comma-delimited field from the SSH_MSG_USERAUTH_PACKET
     */
    protected void setAllowedMethods(String commaDelimed)
    {
        allowed = new HashSet<String>(Arrays.asList(commaDelimed.split(",")));
        log.debug("Allowed = {}", allowed.toString());
    }
    
}
