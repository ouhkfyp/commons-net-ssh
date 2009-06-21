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

import java.util.List;

import org.apache.commons.net.ssh.cipher.Cipher;
import org.apache.commons.net.ssh.compression.Compression;
import org.apache.commons.net.ssh.kex.KeyExchange;
import org.apache.commons.net.ssh.keyprovider.KeyPairProvider;
import org.apache.commons.net.ssh.mac.MAC;
import org.apache.commons.net.ssh.random.Random;
import org.apache.commons.net.ssh.signature.Signature;

/**
 * Allows retrieving all the <code>NamedFactory</code> for Cipher, MAC, etc.
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class FactoryManager
{ 

    private List<NamedFactory<KeyExchange>> keyExchangeFactories;
    private List<NamedFactory<Cipher>> cipherFactories;
    private List<NamedFactory<Compression>> compressionFactories;
    private List<NamedFactory<MAC>> macFactories;
    private List<NamedFactory<Signature>> signatureFactories;
    private NamedFactory<Random> randomFactory;
    private KeyPairProvider keyPairProvider;
    private final String version;
    
    /**
     * An upper case string identifying the version of the software used on
     * client or server side. This version includes the name of the software and
     * usually looks like: <code>SSHD-1.0</code>
     * 
     * @return the version of the software
     */
    public String getVersion() {
        return version;
    }
    
    /**
     * Retrieve the list of named factories for <code>KeyExchange</code>.
     * 
     * @return a list of named <code>KeyExchange</code> factories, never
     *         <code>null</code>
     */
    public List<NamedFactory<KeyExchange>> getKeyExchangeFactories() {
        return keyExchangeFactories;
    }
    
    /**
     * Retrieve the list of named factories for <code>Cipher</code>.
     * 
     * @return a list of named <code>Cipher</code> factories, never
     *         <code>null</code>
     */
    public List<NamedFactory<Cipher>> getCipherFactories() {
        return cipherFactories;
    }
    
    /**
     * Retrieve the list of named factories for <code>Compression</code>.
     * 
     * @return a list of named <code>Compression</code> factories, never
     *         <code>null</code>
     */
    public List<NamedFactory<Compression>> getCompressionFactories() {
        return compressionFactories;
    }
    
    /**
     * Retrieve the list of named factories for <code>MAC</code>.
     * 
     * @return a list of named <code>Mac</code> factories, never
     *         <code>null</code>
     */
    public List<NamedFactory<MAC>> getMACFactories() {
        return macFactories;
    }
    
    /**
     * Retrieve the list of named factories for <code>Signature</code>.
     * 
     * @return a list of named <code>Signature</code> factories, never
     *         <code>null</code>
     */
    public List<NamedFactory<Signature>> getSignatureFactories() {
        return signatureFactories;
    }
    
    /**
     * Retrieve the <code>KeyPairProvider</code> that will be used to find the
     * host key to use on the server side or the user key on the client side.
     * 
     * @return the <code>KeyPairProvider</code>, never <code>null</code>
     */
    public KeyPairProvider getKeyPairProvider() {
        return keyPairProvider;
    }
    
    /**
     * Retrieve the <code>Random</code> factory to be used.
     * 
     * @return the <code>Random</code> factory, never <code>null</code>
     */
    public NamedFactory<Random> getRandomFactory() {
        return randomFactory;
    }
    
    public void setCipherFactories(List<NamedFactory<Cipher>> cipherFactories)
    {
        this.cipherFactories = cipherFactories;
    }
    
    public void setCompressionFactories(List<NamedFactory<Compression>> compressionFactories)
    {
        this.compressionFactories = compressionFactories;
    }
    
    public void setKeyExchangeFactories(List<NamedFactory<KeyExchange>> keyExchangeFactories)
    {
        this.keyExchangeFactories = keyExchangeFactories;
    }
    
    public void setKeyPairProvider(KeyPairProvider keyPairProvider)
    {
        this.keyPairProvider = keyPairProvider;
    }
    
    public void setMACFactories(List<NamedFactory<MAC>> macFactories)
    {
        this.macFactories = macFactories;
    }
    
    public void setRandomFactory(NamedFactory<Random> randomFactory)
    {
        this.randomFactory = randomFactory;
    }
    
    public void setSignatureFactories(List<NamedFactory<Signature>> signatureFactories)
    {
        this.signatureFactories = signatureFactories;
    }

    FactoryManager(String version)
    {
        this.version = version;
    }
    
}
