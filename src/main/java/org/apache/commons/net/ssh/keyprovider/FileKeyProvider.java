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
package org.apache.commons.net.ssh.keyprovider;

import java.io.File;

import org.apache.commons.net.ssh.util.PasswordFinder;

/**
 * A file key provider is initialized with a location of
 */
public interface FileKeyProvider extends KeyProvider
{
    
    enum Format
    {
        PKCS8, OpenSSH, Unknown
    }
    
    void init(File location);
    
    void init(File location, PasswordFinder pwdf);
    
}
