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

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.ServerSocket;

import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.userauth.UserAuthException;
import org.apache.commons.net.ssh.util.BogusPasswordAuthenticator;
import org.apache.sshd.SshServer;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/* Kinda basic right now */

public class SmokeTest
{
    // static
    // {
    // BasicConfigurator.configure(new ConsoleAppender(new PatternLayout("%d [%-15.15t] %-5p %-30.30c{1} - %m%n")));
    // }
    
    private SSHClient ssh;
    private SshServer sshd;
    
    private int port;
    
    private static final String hostkey = "src/test/resources/hostkey.pem";
    private static final String fingerprint = "ce:a7:c1:cf:17:3f:96:49:6a:53:1a:05:0b:ba:90:db";
    
    @Before
    public void setUp() throws IOException
    {
        ServerSocket s = new ServerSocket(0);
        port = s.getLocalPort();
        s.close();
        
        sshd = SshServer.setUpDefaultServer();
        sshd.setPort(port);
        sshd.setKeyPairProvider(new FileKeyPairProvider(new String[] { hostkey }));
        // sshd.setShellFactory(new EchoShellFactory());
        sshd.setPasswordAuthenticator(new BogusPasswordAuthenticator());
        sshd.start();
        
        ssh = new SSHClient();
        ssh.addHostKeyVerifier(fingerprint);
    }
    
    @After
    public void tearUp() throws IOException, InterruptedException
    {
        ssh.disconnect();
        sshd.stop();
    }
    
    @Test
    public void testAuthenticate() throws IOException
    {
        connect();
        authenticate();
        assertTrue(ssh.isAuthenticated());
    }
    
    @Test
    public void testConnect() throws IOException
    {
        connect();
        assertTrue(ssh.isConnected());
    }
    
    // @Test
    // // TODO -- test I/O
    // public void testShell() throws IOException
    // {
    // connect();
    // authenticate();
    //        
    // Shell shell = ssh.startSession().startShell();
    // assertTrue(shell.isOpen());
    //        
    // shell.close();
    // assertFalse(shell.isOpen());
    // }
    
    private void authenticate() throws UserAuthException, TransportException
    {
        ssh.authPassword("same", "same");
    }
    
    private void connect() throws IOException
    {
        ssh.connect("localhost", port);
    }
    
}
