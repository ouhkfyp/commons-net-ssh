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

import java.net.InetSocketAddress;

import org.apache.commons.net.ssh.SSHClient;
import org.apache.commons.net.ssh.connection.Session;
import org.apache.commons.net.ssh.connection.SocketForwardingConnectListener;
import org.apache.commons.net.ssh.connection.Session.Command;
import org.apache.commons.net.ssh.util.Pipe;

/**
 * This example demonstrates how forwarding X11 connections from a remote host can be accomplished.
 */
public class X11
{
    
    // static {
    // BasicConfigurator.configure(new ConsoleAppender(new PatternLayout("%d [%-15.15t] %-5p %-30.30c{1} - %m%n")));
    // }
    
    public static void main(String... args) throws Exception
    {
        SSHClient ssh = new SSHClient();
        
        // Compression makes X11 more feasible over slower connections
        // ssh.useCompression();
        
        ssh.loadKnownHosts();
        
        /*
         * NOTE: Forwarding incoming X connections to localhost:6000 only works if X is started without the
         * "-nolisten tcp" option (this is usually not the default for good reason)
         */
        ssh.registerX11Forwarder(new SocketForwardingConnectListener(new InetSocketAddress("localhost", 6000)));
        
        ssh.connect("localhost");
        try
        {
            
            ssh.authPublickey(System.getProperty("user.name"));
            
            Session sess = ssh.startSession();
            
            /*
             * It is recommendable to send a fake cookie, and in your ConnectListener when a connection comes in replace
             * it with the real one. But here simply one from `xauth list` is being used.
             */
            sess.reqX11Forwarding("MIT-MAGIC-COOKIE-1", "26e8700422fd3efb99a918ce02324e9e", 0);
            
            Command cmd = sess.exec("firefox");
            
            new Pipe("stdout", cmd.getInputStream(), System.out).start();
            new Pipe("stderr", cmd.getErrorStream(), System.err).start();
            
            // Wait for session & X11 channel to get closed
            ssh.getConnection().join();
            
        } finally
        {
            ssh.disconnect();
        }
    }
}