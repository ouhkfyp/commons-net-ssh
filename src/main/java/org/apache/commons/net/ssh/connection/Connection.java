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

import org.apache.commons.net.ssh.Constants;
import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.Session;
import org.apache.commons.net.ssh.util.Buffer;

/*
 * TODO:
 * 
 * This class is a stub. A lot of work to be done in this package; most of July.
 * 
 */

public class Connection implements Service
{
    
    private static final String SERVICE_NAME = "ssh-connection";
    private final Session session;
    
    public Connection(Session session)
    {
        this.session = session;
    }
    
    public String getName()
    {
        return SERVICE_NAME;
    }
    
    public void handle(Constants.Message cmd, Buffer packet)
    {
    }
    
}
