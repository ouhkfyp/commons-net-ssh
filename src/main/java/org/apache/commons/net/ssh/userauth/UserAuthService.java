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
import org.apache.commons.net.ssh.TransportException;
import org.apache.commons.net.ssh.util.LQString;

/**
 * The {@code "ssh-userauth"} service.
 * 
 * @author shikhar
 */
public interface UserAuthService extends Service
{
    
    /**
     * The assigned name for this service.
     */
    String NAME = "ssh-userauth";
    
    /**
     * Attempts authentication.
     * 
     * @return {@code true} if authentication succeeded completely, {@code false} if authentiation
     *         was partially successful
     * @throws UserAuthException
     *             if authentication failed
     * @throws TransportException
     *             if there was a transport error during authentication
     */
    boolean authenticate() throws UserAuthException, TransportException;
    
    /**
     * Returns the authentication banner (if any)
     * 
     * @return the banner, or {@code null} if none was received
     */
    LQString getBanner();
    
}
