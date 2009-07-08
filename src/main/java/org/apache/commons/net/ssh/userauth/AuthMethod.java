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
import java.util.Set;

import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.TransportException;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Constants.Message;

/**
 * An authentication method of the <a href="http://www.ietf.org/rfc/rfc4252.txt">SSH Authentication
 * Protocol</a>.
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @author Shikhar Bhushan
 * @see UserAuthProtocol
 */
public interface AuthMethod
{
    
    /**
     * The result of this method
     */
    enum Result
    {
        /** Succesfully authenticated */
        SUCCESS,

        /** Not concluded yet, wants next packet directed to this method */
        CONTINUED,

        /** Multiple authentications were required - one hurdle down, continue trying */
        PARTIAL_SUCCESS,

        /** Failed to authenticate using this method */
        FAILURE,

        /** Indeterminable */
        UNKNOWN,
    }
    
    /**
     * Authentication methods that may be allowed to continue. Only initialized in case the result
     * of {@link #handle} is {@link Result#FAILURE}, and otherwise will be {@code null}.
     * 
     * @return the methods allowoed to continue
     */
    Set<String> getAllowedMethods();
    
    /**
     * Returns the assigned name for this authentication method.
     */
    String getName();
    
    /**
     * Returns the next {@link Service} that will be started if authentication using this method is
     * successful.
     */
    Service getNextService();
    
    /**
     * Returns the username this method is trying to authenticate / has authenticated.
     */
    String getUsername();
    
    /**
     * Asks this instance to handle the specified packet.
     * 
     * @param cmd
     *            the SSH message identifier
     * @param buf
     *            buffer containing rest of the packet
     * @return the determined {@link Result}
     * @throws UserAuthException
     * @throws TransportException
     */
    Result handle(Message cmd, Buffer buf) throws UserAuthException, TransportException;
    
    /**
     * Request this method.
     * 
     * @throws IOException
     */
    void request() throws UserAuthException, TransportException;
    
}
