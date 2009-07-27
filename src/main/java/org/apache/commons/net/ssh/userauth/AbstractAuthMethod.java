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
    
    protected AuthParams params;
    
    public void handle(Message cmd, Buffer buf) throws UserAuthException, TransportException
    {
        throw new UserAuthException("Unknown packet received during " + getName() + ": " + cmd);
    }
    
    public void init(AuthParams params)
    {
        this.params = params;
    }
    
    public void request() throws UserAuthException, TransportException
    {
        params.getTransport().writePacket(buildReq());
    }
    
    public boolean shouldRetry()
    {
        return false;
    }
    
    protected Buffer buildReq() throws UserAuthException
    {
        return new Buffer(Message.USERAUTH_REQUEST) // SSH_MSG_USERAUTH_REQUEST
                                                   .putString(params.getUsername()) // username goes first
                                                   .putString(params.getNextServiceName()) // the service that we'd like on success
                                                   .putString(getName()); // name of auth method
        
    }
    
}
