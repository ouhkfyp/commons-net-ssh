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

import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Constants.Message;

public interface Service
{
    /**
     * Get the assignmed name for this SSH service.
     * 
     * @return service name
     */
    String getName();
    
    /**
     * @return the {@link Session} associated with this service
     */
    Session getSession();
    
    /**
     * Transport layer notifying that a SSH_MSG_UNIMPLEMENTED was received for packet with given
     * sequence number
     * 
     * @param seqNum
     */
    void gotUnimplemented(int seqNum);
    
    /**
     * SSH packets not recognized by the transport layer are passed to the service instance for
     * handling.
     * 
     * @param cmd
     * @param packet
     * @throws IOException
     */
    void handle(Message cmd, Buffer packet) throws SSHException;
    
    /**
     * Notifies this instance that an error occured in the transport layer.
     * 
     * @param ex
     *            the exception that occured in session layer
     */
    void notifyError(SSHException ex);
    
    /**
     * Request and install this service.
     * 
     * @throws IOException
     */
    void request() throws SSHException;
    
}
