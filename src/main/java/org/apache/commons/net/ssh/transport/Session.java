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
package org.apache.commons.net.ssh.transport;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.PublicKey;

import org.apache.commons.net.ssh.FactoryManager;
import org.apache.commons.net.ssh.SSHException;
import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Constants;

/**
 * TODO javadocs
 * 
 * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
 */
public interface Session
{
    
    /**
     * Interface for host key verification.
     * 
     * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
     */
    interface HostKeyVerifier
    {
        
        /**
         * This is the callback that is called when the server's host key needs to be verified, and
         * its return value indicates whether the SSH connection should proceed.
         * <p>
         * <b>Note</b>: host key verification is the basis for security in SSH, therefore exercise
         * due caution in implementing!
         * 
         * @param address
         *            remote address we are connected to
         * @param key
         *            public key provided server
         * @return <code>true</code> if key acceptable, <code>false</code> otherwise
         */
        boolean verify(InetAddress address, PublicKey key);
        
    }
    
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
     * Send a disconnection packet with reason as {@link Constants#SSH_DISCONNECT_BY_APPLICATION}
     * and closoe the session.
     * 
     * @throws IOException
     */
    void disconnect() throws IOException;
    
    /**
     * Send a disconnect packet with the given reason and close the session.
     * 
     * @param reason
     * @throws IOException
     */
    void disconnect(int reason) throws IOException;
    
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
    
    Service getActiveService();
    
    String getClientVersion();
    
    /**
     * Retrieve the factory manager
     * 
     * @return the factory manager for this session
     */
    FactoryManager getFactoryManager();
    
    String getServerVersion();
    
    /**
     * Do kex
     * 
     * @param socket
     * @throws SSHException
     */
    void init(Socket socket) throws IOException;
    
    boolean isRunning();
    
    /**
     * Request a service. Implicitly sets the active service instance, so a call to
     * {@link #setService(Service)} is not needed.
     * 
     * @param service
     * @throws Exception
     */
    void reqService(Service service) throws IOException;
    
    /**
     * Must be called after the session has been authenticated, so that delayed compression may
     * become effective if applicable.
     * 
     * @param authed
     */
    void setAuthenticated();
    
    /**
     * Specify the callback for host key verification.
     * 
     * @param hkv
     * @see HostKeyVerifier#verify(java.net.InetAddress, java.security.PublicKey)
     */
    void setHostKeyVerifier(HostKeyVerifier hkv);
    
    /**
     * Set the currently active service, to which handling of incoming packets is delegated by
     * calling its {@link Service#handle(Constants.Message, Buffer)} method.
     * 
     * @param service
     */
    void setService(Service service);
    
    /**
     * Encode <code>payload</code> as an SSH packet and send it over the output stream for this
     * session. It is guaranteed that packets are sent according to the order of invocation.
     * 
     * Implementation required to be thread-safe.
     * 
     * @param payload
     * @throws IOException
     * @return the sequence no. of the packet written
     */
    int writePacket(Buffer payload) throws IOException;
    
}
