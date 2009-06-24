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
import org.apache.commons.net.ssh.PasswordFinder;
import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.Session;
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
    
    public enum State
    {
        NONE, ONGOING, DONE
    }
    
    public static final String serviceName = "ssh-userauth";
    
    private final Session session;
    private final String nextServiceName;
    
    private final String[] allowedMethods = { "publickey", "password" };
    private String banner;
    private final State state = State.NONE;
    
    private Method method; // currently active method
    
    public UserAuth(Session session, String nextServiceName)
    {
        this.session = session;
        this.nextServiceName = nextServiceName;
    }
    
    public void authPassword(String username, PasswordFinder pwdf) throws IOException
    {
        request(username);
    }
    
    public String getBanner()
    {
        return banner;
    }
    
    public String getName()
    {
        return serviceName;
    }
    
    public void handle(Constants.Message cmd, Buffer packet)
    {
        switch (cmd)
        {
        case SSH_MSG_USERAUTH_BANNER:
            banner = packet.getString();
            break;
        case SSH_MSG_USERAUTH_SUCCESS:
            session.setAuthenticated(true);
            break;
        default:

        }
    }
    
    private void request(String username) throws IOException
    {
        Buffer buffer = session.createBuffer(Constants.Message.SSH_MSG_USERAUTH_REQUEST);
        buffer.putString(username);
        buffer.putString(nextServiceName);
        method.updateRequest(buffer);
        session.writePacket(buffer);
    }
    
}
