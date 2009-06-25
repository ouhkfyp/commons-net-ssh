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

import org.apache.commons.net.ssh.Constants;
import org.apache.commons.net.ssh.util.Buffer;

/*
 * TODO:
 * 
 * > finish by end-of-month
 * 
 * .... once done:
 * 
 * > document
 * 
 * > unit tests
 * 
 */

/**
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public interface Method
{
    
    enum Result
    {
        SUCCESS, //
        CONTINUED, //
        PARTIAL_SUCCESS, //
        FAILURE, //
    }
    
    void buildRequest(Buffer buf);
    
    /**
     * Authentication methods that may be allowed to continue. Only set in case the result of
     * {@link #next(Buffer)} is {@link Result#FAILURE}, otherwise will be <code>null</code>.
     * 
     * @return array of strings e.g. {"publickey", "password", "keyboard-interactive"}
     */
    String[] getAllowedMethods();
    
    String getName();
    
    Result next(Constants.Message cmd, Buffer buf) throws Exception;
}
