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

import org.apache.commons.net.ssh.SSHException;
import org.apache.commons.net.ssh.util.FriendlyChainer;
import org.apache.commons.net.ssh.util.Constants.DisconnectReason;

/**
 * User authentication exception
 * 
 * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
 */
public class UserAuthException extends SSHException
{
    
    public static final FriendlyChainer<UserAuthException> chainer = new FriendlyChainer<UserAuthException>()
        {
            
            public UserAuthException chain(Throwable t)
            {
                if (t instanceof UserAuthException)
                    return (UserAuthException) t;
                else
                    return new UserAuthException(t);
            }
            
        };
    
    public UserAuthException()
    {
        super();
    }
    
    public UserAuthException(DisconnectReason code)
    {
        super(code);
    }
    
    public UserAuthException(DisconnectReason code, String message)
    {
        super(code, message);
    }
    
    public UserAuthException(DisconnectReason code, String message, Throwable cause)
    {
        super(code, message, cause);
    }
    
    public UserAuthException(DisconnectReason code, Throwable cause)
    {
        super(code, cause);
    }
    
    public UserAuthException(String message)
    {
        super(message);
    }
    
    public UserAuthException(String message, Throwable cause)
    {
        super(message, cause);
    }
    
    public UserAuthException(Throwable cause)
    {
        super(cause);
    }
    
}
