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

import org.apache.commons.net.ssh.Constants;
import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.transport.Session;
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

public class UserAuth implements Service
{
    
    public static final String NAME = "ssh-userauth";
    
    private final Session session;
    
    private final String[] allowedMethods = { "publickey", "password" };
    private String banner;
    
    private Method method; // currently active method
    
    public UserAuth(Session session)
    {
        this.session = session;
    }
    
    public void authenticateWith(Method method) throws IOException
    {
        this.method = method;
        request();
    }
    
    public void authPassword(String username, String nextService, PasswordFinder pwdf)
            throws IOException
    {
        authenticateWith(new MethPassword(session, username, nextService, pwdf));
    }
    
    private void failure()
    {
        
    }
    
    public String getBanner()
    {
        return banner;
    }
    
    public String getName()
    {
        return NAME;
    }
    
    public void handle(Constants.Message cmd, Buffer packet) throws Exception
    {
        switch (cmd)
        {
        case SSH_MSG_USERAUTH_BANNER:
            banner = packet.getString();
            break;
        default:
            switch (method.next(cmd, packet))
            {
            case SUCCESS:
                success();
            case FAILURE:
                failure();
            case PARTIAL_SUCCESS:
                success();
            case CONTINUED:
                break;
            default:
                assert false;
            }
        }
    }
    
    private void request() throws IOException
    {
        Buffer buffer = session.createBuffer(Constants.Message.SSH_MSG_USERAUTH_REQUEST);
        method.buildRequest(buffer);
        session.writePacket(buffer);
    }
    
    public void setError(Exception ex)
    {
        // TODO Auto-generated method stub
        
    }
    
    private void success()
    {
        // TODO Auto-generated method stub
        
    }
    
}
// /**
// * Authentication methods that may be allowed to continue. Only set in case the result of
// * {@link #next(Buffer)} is {@link Result#FAILURE}, otherwise will be <code>null</code>.
// *
// * @return array of strings e.g. {"publickey", "password", "keyboard-interactive"}
// */
