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
import org.apache.commons.net.ssh.util.Buffer;

/**
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface AuthMethod
{
    
    enum Result
    {
        SUCCESS, // authentication successful
        CONTINUED, // no conclusion yet, wants next packet directed to it
        PARTIAL_SUCCESS, // multiple authentications required - one step down, continue trying
        FAILURE, // failed to authenticate using this method
        UNKNOWN, // indeterminable
    }
    
    /**
     * Authentication methods that may be allowed to continue. Only initialized in case the result
     * of {@link #next(Buffer)} is {@link Result#FAILURE}, and otherwise will be <code>null</code>.
     * 
     * @return array of strings e.g. {"publickey", "password", "keyboard-interactive"}
     */
    Set<String> getAllowedMethods();
    
    String getName();
    
    Service getNextService();
    
    String getUsername();
    
    Result handle(Message cmd, Buffer buf) throws IOException;
    
    void request() throws IOException;
    
}
