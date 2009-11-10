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

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.commons.net.ssh.util.Constants.KeyType;

/**
 * A {@link KeyProvider} wrapper around {@link java.security.KeyPair}
 */
public class KeyPairWrapper implements KeyProvider
{
    private final KeyPair kp;
    private final KeyType type;
    
    public KeyPairWrapper(KeyPair kp)
    {
        this.kp = kp;
        type = KeyType.fromKey(kp.getPublic());
    }
    
    public KeyPairWrapper(PublicKey publicKey, PrivateKey privateKey)
    {
        this(new KeyPair(publicKey, privateKey));
    }
    
    public PrivateKey getPrivate()
    {
        return kp.getPrivate();
    }
    
    public PublicKey getPublic()
    {
        return kp.getPublic();
    }
    
    public KeyType getType()
    {
        return type;
    }
    
}
