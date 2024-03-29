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
package org.apache.commons.net.ssh.sftp;

import org.apache.commons.net.ssh.SSHException;
import org.apache.commons.net.ssh.sftp.Response.StatusCode;
import org.apache.commons.net.ssh.util.FriendlyChainer;
import org.apache.commons.net.ssh.util.Constants.DisconnectReason;

public class SFTPException extends SSHException
{
    
    public static final FriendlyChainer<SFTPException> chainer = new FriendlyChainer<SFTPException>()
    {
        
        public SFTPException chain(Throwable t)
        {
            if (t instanceof SFTPException)
                return (SFTPException) t;
            else
                return new SFTPException(t);
        }
        
    };
    
    public SFTPException()
    {
        super();
    }
    
    public SFTPException(DisconnectReason code)
    {
        super(code);
    }
    
    public SFTPException(DisconnectReason code, String message)
    {
        super(code, message);
    }
    
    public SFTPException(DisconnectReason code, String message, Throwable cause)
    {
        super(code, message, cause);
    }
    
    public SFTPException(DisconnectReason code, Throwable cause)
    {
        super(code, cause);
    }
    
    public SFTPException(String message)
    {
        super(message);
    }
    
    public SFTPException(String message, Throwable cause)
    {
        super(message, cause);
    }
    
    public SFTPException(Throwable cause)
    {
        super(cause);
    }
    
    private StatusCode sc;
    
    public StatusCode getStatusCode()
    {
        return (sc == null) ? StatusCode.UNKNOWN : sc;
        
    }
    
    public SFTPException(StatusCode sc, String msg)
    {
        this(msg);
        this.sc = sc;
    }
    
}
