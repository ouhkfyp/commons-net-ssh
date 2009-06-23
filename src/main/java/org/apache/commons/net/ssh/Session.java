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

import java.io.IOException;
import java.net.Socket;

import org.apache.commons.net.ssh.util.Buffer;

/**
 * TODO javadocs
 * 
 * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
 */
public interface Session
{
    
    /**
     * Create a new buffer for the specified SSH packet and reserve the needed space (5 bytes) for
     * the packet header.
     * 
     * @param cmd
     *            the SSH command
     * @return a new buffer ready for write
     */
    Buffer createBuffer(Constants.Message cmd);
    
    /**
     * Send a disconnect packet with the given reason and message, and close the session.
     * 
     * @param reason
     *            the reason code for this disconnect
     * @param msg
     *            the text message
     * @throws IOException
     *             if an error occured sending the packet
     */
    void disconnect(int reason, String msg) throws IOException;
    
    String getClientVersion();
    
    /**
     * Retrieve the factory manager
     * 
     * @return the factory manager for this session
     */
    FactoryManager getFactoryManager();
    
    String getServerVersion();
    
    void init(Socket socket) throws Exception;
    
    boolean isRunning();
    
    void setAuthenticated(boolean authed);
    
    void setHostKeyVerifier(HostKeyVerifier hkv);
    
    void startService(Service service) throws Exception;
    
    /**
     * Encode the payload as an SSH packet and send it over the session.
     * 
     * @param payload
     * @throws IOException
     */
    int writePacket(Buffer payload) throws IOException;
    
}
