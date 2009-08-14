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
package org.apache.commons.net.ssh.connection;

import org.apache.commons.net.ssh.SSHException;
import org.apache.commons.net.ssh.util.FriendlyChainer;
import org.apache.commons.net.ssh.util.Constants.DisconnectReason;

/**
 * Connection-layer exception.
 * 
 * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
 */
public class ConnectionException extends SSHException
{
    
    public static final FriendlyChainer<ConnectionException> chainer = new FriendlyChainer<ConnectionException>()
        {
            public ConnectionException chain(Throwable t)
            {
                if (t instanceof ConnectionException)
                    return (ConnectionException) t;
                else
                    return new ConnectionException(t);
            }
        };
    
    public ConnectionException()
    {
        super();
    }
    
    public ConnectionException(DisconnectReason code)
    {
        super(code);
    }
    
    public ConnectionException(DisconnectReason code, String message)
    {
        super(code, message);
    }
    
    public ConnectionException(DisconnectReason code, String message, Throwable cause)
    {
        super(code, message, cause);
    }
    
    public ConnectionException(DisconnectReason code, Throwable cause)
    {
        super(code, cause);
    }
    
    public ConnectionException(String message)
    {
        super(message);
    }
    
    public ConnectionException(String message, Throwable cause)
    {
        super(message, cause);
    }
    
    public ConnectionException(Throwable cause)
    {
        super(cause);
    }
    
}
