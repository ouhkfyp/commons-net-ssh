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
package org.apache.commons.net.ssh.cipher;

import org.apache.commons.net.ssh.Cipher;
import org.apache.commons.net.ssh.NamedFactory;

/**
 * BlowfishCBC Cipher
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class BlowfishCBC extends BaseCipher
{
    
    /**
     * Named factory for BlowfishCBC Cipher
     */
    public static class Factory implements NamedFactory<Cipher>
    {
        public Cipher create()
        {
            return new BlowfishCBC();
        }
        
        public String getName()
        {
            return "blowfish-cbc";
        }
    }
    
    public BlowfishCBC()
    {
        super(8, 16, "Blowfish", "Blowfish/CBC/NoPadding");
    }
    
}