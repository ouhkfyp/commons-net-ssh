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

import org.apache.commons.net.ssh.connection.ConnectionService;
import org.apache.commons.net.ssh.userauth.UserAuthService;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Constants.Message;

/**
 * Represents a service running on top of the SSH protocol transport layer.
 * 
 * @author shikhar
 * @see UserAuthService
 * @see ConnectionService
 */
public interface Service
{
    /**
     * Get the assignmed name for this SSH service.
     * 
     * @return service name
     */
    String getName();
    
    /**
     * Getter for the {@link Session} instance for this service
     * 
     * @return the session
     */
    Session getSession();
    
    /**
     * Asks this service to handle a particular packet.
     * 
     * Meant as a callback for the transport layer so it can deliver packets meant for the active
     * service.
     * 
     * @param cmd
     *            the message identifier
     * @param buffer
     *            the buffer containing rest of the packet
     * @throws SSHException
     */
    void handle(Message cmd, Buffer buffer) throws SSHException;
    
    /**
     * Notifies this instance of an error in the transport layer.
     * 
     * Meant as a callback for transport layer.
     * 
     * @param ex
     *            the exception that occured in session layer
     */
    void notifyError(SSHException ex);
    
    /**
     * Notifies this service that a SSH_MSG_UNIMPLEMENTED was received for packet with given
     * sequence number.
     * 
     * Meant as a callback for transport layer.
     * 
     * @param seqNum
     */
    void notifyUnimplemented(int seqNum);
    
    /**
     * Request and install this service with the session.
     * 
     * @throws SSHException
     */
    void request() throws SSHException;
    
}
