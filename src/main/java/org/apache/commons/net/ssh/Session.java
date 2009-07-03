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

import org.apache.commons.net.ssh.Constants.DisconnectReason;
import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.util.Buffer;

/**
 * Transport layer of the SSH protocol.
 * 
 * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
 */
public interface Session
{
    
    /**
     * Specify a callback for host key verification.
     * 
     * @param hkv
     * @see HostKeyVerifier#verify(java.net.InetAddress, java.security.PublicKey)
     */
    void addHostKeyVerifier(HostKeyVerifier hkv);
    
    /**
     * Send a disconnection packet with reason as {@link Constants#SSH_DISCONNECT_BY_APPLICATION},
     * and close the session.
     */
    boolean disconnect();
    
    /**
     * Send a disconnect packet with the given reason, and close this session.
     */
    boolean disconnect(DisconnectReason reason);
    
    /**
     * Send a disconnect packet with the given reason and message, and close this session.
     * 
     * @param reason
     *            the reason code for this disconnect
     * @param msg
     *            the text message
     */
    boolean disconnect(DisconnectReason reason, String msg);
    
    Service getService();
    
    /**
     * Returns the version string used by this client to identify itself to an SSH server.
     * 
     * @return client's version string
     */
    String getClientVersion();
    
    /**
     * Retrieves the {@link FactoryManager} associated with this session.
     * 
     * @return factory manager for this session
     */
    FactoryManager getFactoryManager();
    
    /**
     * Returns the session identifier computed during key exchange.
     * 
     * @return session identifier as a byte array
     */
    byte[] getID();
    
    long getLastSeqNum();
    
    /**
     * Returns the version string as sent by the SSH server for identification purposes.
     * 
     * If the session has not been initialized, will be {@code null}.
     * 
     * @return server's version string
     */
    String getServerVersion();
    
    /**
     * Initializes this session by exchanging identification information and performing key exchange
     * with the SSH server.
     * <p>
     * When this method returns, it is ready for requesting a SSH service (typically,
     * authentication).
     * 
     * @param socket
     *            the socket on which connection to SSH server has been already established
     * @throws SSHException
     *             if there is an error during session initialization or key exchange
     */
    void init(Socket socket) throws IOException;
    
    boolean isRunning();
    
    /**
     * Request a SSH service represented by a {@link Service} instance.
     * <p>
     * If the request was successful, the active service is set implicitly and a call to
     * {@link #setService(Service)} is not needed.
     * 
     * @param service
     * @throws IOException
     *             if the request failed for any reason
     */
    void reqService(Service service) throws TransportException;
    
    /**
     * This method <b>must</b> be called after the session has been authenticated, so that delayed
     * compression may become effective if applicable.
     */
    void setAuthenticated();
    
    /**
     * Sets the currently active service, to which handling of packets not understood by the
     * transport layer is delegated.
     * <p>
     * Delegation of message-handling is done by calling the {@link Service#handle(Message, Buffer)}
     * method.
     * 
     * @param service
     */
    void setService(Service service);
    
    /**
     * Encodes and sends an SSH packet over the output stream for this session.
     * 
     * @param payload
     *            the {@link Buffer} with the payload
     * @throws IOException
     *             if the packet could not be sent
     * @return the sequence no. of the sent packet
     */
    long writePacket(Buffer payload) throws TransportException;
    
}
