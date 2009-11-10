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
package examples.ssh;

import org.apache.commons.net.ssh.SSHClient;
import org.apache.commons.net.ssh.scp.SCPUploadClient;

/**
 * This example demonstrates uploading of a file over SCP to the SSH server.
 */
public class SCPUpload
{
    
    // static {
    // BasicConfigurator.configure(new ConsoleAppender(new PatternLayout("%d [%-15.15t] %-5p %-30.30c{1} - %m%n")));
    // }
    
    public static void main(String[] args) throws Exception
    {
        SSHClient ssh = new SSHClient();
        ssh.loadKnownHosts();
        ssh.connect("localhost");
        try
        {
            ssh.authPublickey(System.getProperty("user.name"));
            
            // Compression = significant speedup for large file transfers on fast links
            // present here to demo renegotiation - could have just put this before connect()
            ssh.useCompression();
            
            new SCPUploadClient(ssh).copy("/tmp/ten", ".");
            
        } finally
        {
            ssh.disconnect();
        }
    }
    
}