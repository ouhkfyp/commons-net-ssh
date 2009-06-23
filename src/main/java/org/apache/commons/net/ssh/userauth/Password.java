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
import org.apache.commons.net.ssh.util.Buffer;

public class Password extends Method
{
    
    public static final String methodName = "password";
    
    private final String username;
    private final PasswordFinder pwdf;
    
    Password(String username, PasswordFinder pwdf)
    {
        this.username = username;
        this.pwdf = pwdf;
    }
    
    @Override
    public Result next(Constants.Message cmd, Buffer buffer) throws IOException
    {
        return null;
    }
    
    @Override
    void updateRequest(Buffer buf)
    {
        buf.putString(methodName);
        buf.putBoolean(false);
        buf.putString(pwdf.getPassword());
    }
    
}
