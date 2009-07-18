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

import org.apache.commons.net.ssh.keyprovider.KeyProvider;
import org.apache.commons.net.ssh.util.Buffer;

/**
 * Implements the "hostbased" SSH authentication method.
 * 
 * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
 */
public class AuthHostbased extends KeyedAuthMethod
{
    
    /**
     * Assigned name of this authentication method
     */
    public static final String NAME = "hostbased";
    
    protected final String hostname;
    protected final String hostuser;
    
    public AuthHostbased(KeyProvider kProv, String hostuser)
    {
        this(kProv, hostuser, null);
    }
    
    public AuthHostbased(KeyProvider kProv, String hostuser, String hostname)
    {
        super(kProv);
        assert hostuser != null;
        this.hostuser = hostuser;
        this.hostname = hostname;
    }
    
    public String getName()
    {
        return NAME;
    }
    
    @Override
    protected Buffer buildReq() throws UserAuthException
    {
        Buffer req = putPubKey(super.buildReq());
        req.putString(hostname == null ? params.getTransport().getRemoteHost().getHostName() : hostname) //
           .putString(hostuser);
        return putSig(req);
    }
    
}
