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

import java.util.Deque;

import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.transport.TransportException;

/**
 * User authentication API
 */
public interface UserAuth
{
    
    /**
     * Attempt to authenticate {@code username} using each of {@link methods} in order. {@code
     * nextService} is the {@link Service} that will be enabled on successful authentication.
     * <p>
     * Authentication fails if there are no methods available, i.e. if all the methods failed or
     * there were methods available but could not be attempted because the server did not allow
     * them. In this case, a {@code UserAuthException} is thrown with its cause as the last
     * authentication failure. Other {@code UserAuthException}'s which may have been ignored may be
     * accessed via {@link #getSavedExceptions()}.
     * <p>
     * Futher attempts may also be made by catching {@code UserAuthException} and retrying with this
     * method.
     * 
     * @param username
     *            the user to authenticate
     * @param nextService
     *            the service to set on successful authentication
     * @param methods
     *            the {@link AuthMethod}'s to try
     * @throws UserAuthException
     *             in case of authentication failure
     * @throws TransportException
     *             if there was a transport-layer error
     */
    void authenticate(String username, Service nextService, Iterable<AuthMethod> methods) throws UserAuthException,
            TransportException;
    
    /**
     * Returns the authentication banner (if any). In some cases this is available even before the
     * first authentication request has been made.
     * 
     * @return the banner, or {@code null} if none was received
     */
    String getBanner();
    
    /**
     * Returns saved exceptions that might have been ignored because there were more authentication
     * methods available.
     */
    Deque<UserAuthException> getSavedExceptions();
    
    /**
     * Returns the {@code timeout} for a method to successfully authenticate before it is abandoned.
     */
    int getTimeout();
    
    /**
     * Returns whether authentication was partially successful. Some server's may be configured to
     * require multiple authentications; and this value will be {@code true} if at least one of the
     * methods supplied succeeded.
     * 
     * @return
     */
    boolean hadPartialSuccess();
    
    /**
     * Set the {@code timeout} for any method to successfully authenticate before it is abandoned.
     * 
     * @param timeout
     *            the timeout in seconds
     */
    void setTimeout(int timeout);
    
}
