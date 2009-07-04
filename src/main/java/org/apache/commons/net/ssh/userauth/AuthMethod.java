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
import org.apache.commons.net.ssh.Constants.Message;
import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.util.Buffer;

/**
 * Represents an SSH authentication method for the SSH Authentication Protocol
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
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
     * of {@link #next(Buffer)} is {@link Result#FAILURE}, and otherwise will be <code>null</code>.
     * 
     * @return array of strings e.g. {"publickey", "password", "keyboard-interactive"}
     */
    Set<String> getAllowedMethods();
    
    /**
     * The assigned name for this authentication method.
     * 
     * @return
     */
    String getName();
    
    /**
     * 
     * @return
     */
    Service getNextService();
    
    /**
     * The user this method is trying to authenticate / has authenticated.
     * 
     * @return
     */
    String getUsername();
    
    /**
     * Ask this method to handle the received packet
     * 
     * @param cmd
     * @param buf
     * @return the determined {@link Result}
     * @throws IOException
     */
    Result handle(Message cmd, Buffer buf) throws UserAuthException, TransportException;
    
    /**
     * Request this method
     * 
     * @throws IOException
     */
    void request() throws UserAuthException, TransportException;
    
}
