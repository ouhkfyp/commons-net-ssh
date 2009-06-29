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
import java.util.List;

import org.apache.commons.net.ssh.NamedFactory;
import org.apache.commons.net.ssh.SSHException;
import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.cipher.Cipher;
import org.apache.commons.net.ssh.compression.Compression;
import org.apache.commons.net.ssh.kex.KeyExchange;
import org.apache.commons.net.ssh.keyprovider.KeyPairProvider;
import org.apache.commons.net.ssh.mac.MAC;
import org.apache.commons.net.ssh.random.Random;
import org.apache.commons.net.ssh.signature.Signature;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Constants.Message;

/**
 * TODO javadocs
 * 
 * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
 */
public interface Session
{
    
    /**
     * Allows retrieving all the <code>NamedFactory</code> for Cipher, MAC, etc.
     * 
     * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
     * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
     */
    class FactoryManager
    {
        
        private List<NamedFactory<KeyExchange>> keyExchangeFactories;
        private List<NamedFactory<Cipher>> cipherFactories;
        private List<NamedFactory<Compression>> compressionFactories;
        private List<NamedFactory<MAC>> macFactories;
        private List<NamedFactory<Signature>> signatureFactories;
        private NamedFactory<Random> randomFactory;
        private KeyPairProvider keyPairProvider;
        
        /**
         * Retrieve the list of named factories for <code>Cipher</code>.
         * 
         * @return a list of named <code>Cipher</code> factories, never <code>null</code>
         */
        public List<NamedFactory<Cipher>> getCipherFactories()
        {
            return cipherFactories;
        }
        
        /**
         * Retrieve the list of named factories for <code>Compression</code>.
         * 
         * @return a list of named <code>Compression</code> factories, never <code>null</code>
         */
        public List<NamedFactory<Compression>> getCompressionFactories()
        {
            return compressionFactories;
        }
        
        /**
         * Retrieve the list of named factories for <code>KeyExchange</code>.
         * 
         * @return a list of named <code>KeyExchange</code> factories, never <code>null</code>
         */
        public List<NamedFactory<KeyExchange>> getKeyExchangeFactories()
        {
            return keyExchangeFactories;
        }
        
        /**
         * Retrieve the <code>KeyPairProvider</code> that will be used to find the host key to use
         * on the server side or the user key on the client side.
         * 
         * @return the <code>KeyPairProvider</code>, never <code>null</code>
         */
        public KeyPairProvider getKeyPairProvider()
        {
            return keyPairProvider;
        }
        
        /**
         * Retrieve the list of named factories for <code>MAC</code>.
         * 
         * @return a list of named <code>Mac</code> factories, never <code>null</code>
         */
        public List<NamedFactory<MAC>> getMACFactories()
        {
            return macFactories;
        }
        
        /**
         * Retrieve the <code>Random</code> factory to be used.
         * 
         * @return the <code>Random</code> factory, never <code>null</code>
         */
        public NamedFactory<Random> getRandomFactory()
        {
            return randomFactory;
        }
        
        /**
         * Retrieve the list of named factories for <code>Signature</code>.
         * 
         * @return a list of named <code>Signature</code> factories, never <code>null</code>
         */
        public List<NamedFactory<Signature>> getSignatureFactories()
        {
            return signatureFactories;
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
        
    }
    
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
    Buffer createBuffer(Message cmd);
    
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
    
    /**
     * Session ID
     */
    public byte[] getID();
    
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
     * calling its {@link Service#handle(Message, Buffer)} method.
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
