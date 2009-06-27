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
package org.apache.commons.net.ssh;

import java.io.IOException;

/**
 * TODO Add javadoc
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SSHException extends IOException
{
    
    public static void chain(Exception e) throws SSHException
    {
        if (e instanceof SSHException)
            throw (SSHException) e;
        else
            throw new SSHException(e);
    }
    
    private final int disconnectCode;
    
    public SSHException()
    {
        this(0, null, null);
    }
    
    public SSHException(int disconnectCode)
    {
        this(disconnectCode, null, null);
    }
    
    public SSHException(int disconnectCode, String message)
    {
        this(disconnectCode, message, null);
    }
    
    public SSHException(int disconnectCode, String message, Throwable cause)
    {
        super(message);
        this.disconnectCode = disconnectCode;
        if (cause != null)
            initCause(cause);
    }
    
    public SSHException(int disconnectCode, Throwable cause)
    {
        this(disconnectCode, null, cause);
    }
    
    public SSHException(String message)
    {
        this(0, message, null);
    }
    
    public SSHException(String message, Throwable cause)
    {
        this(0, message, cause);
    }
    
    public SSHException(Throwable cause)
    {
        this(0, null, cause);
    }
    
    public int getDisconnectCode()
    {
        return disconnectCode;
    }
    
}
