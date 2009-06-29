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
import java.util.Set;

import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.transport.Session;
import org.apache.commons.net.ssh.util.Buffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractAuthMethod implements AuthMethod
{
    protected final Logger log = LoggerFactory.getLogger(getClass());
    
    protected final Session session;
    protected final Service nextService;
    protected final String username;
    protected Set<String> allowed;
    
    public AbstractAuthMethod(Session session, Service nextService, String username)
    {
        assert session != null && nextService != null && username != null;
        this.session = session;
        this.nextService = nextService;
        this.username = username;
    }
    
    abstract protected Buffer buildRequest();
    
    public Buffer buildRequestCommon(Buffer buf)
    {
        buf.putString(username);
        buf.putString(nextService.getName());
        buf.putString(getName());
        return buf;
    }
    
    public Set<String> getAllowedMethods()
    {
        return allowed;
    }
    
    public Service getNextService()
    {
        return nextService;
    }
    
    public String getUsername()
    {
        return username;
    }
    
    public void request() throws IOException
    {
        log.debug("Sending SSH_MSG_USERAUTH_REQUEST");
        session.writePacket(buildRequest());
    }
    
    protected void setAllowedMethods(String commaDelimed)
    {
        allowed = new LinkedHashSet<String>(Arrays.asList(commaDelimed.split(",")));
    }
    
}
