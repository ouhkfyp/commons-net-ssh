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

import static org.apache.commons.net.ssh.util.Constants.DEFAULT_PORT;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import org.apache.commons.net.SocketClient;
import org.apache.commons.net.ssh.cipher.AES128CBC;
import org.apache.commons.net.ssh.cipher.AES192CBC;
import org.apache.commons.net.ssh.cipher.AES256CBC;
import org.apache.commons.net.ssh.cipher.BlowfishCBC;
import org.apache.commons.net.ssh.cipher.Cipher;
import org.apache.commons.net.ssh.cipher.TripleDESCBC;
import org.apache.commons.net.ssh.compression.Compression;
import org.apache.commons.net.ssh.compression.CompressionDelayedZlib;
import org.apache.commons.net.ssh.compression.CompressionNone;
import org.apache.commons.net.ssh.compression.CompressionZlib;
import org.apache.commons.net.ssh.connection.ConnectionProtocol;
import org.apache.commons.net.ssh.connection.ConnectionService;
import org.apache.commons.net.ssh.kex.DHG1;
import org.apache.commons.net.ssh.kex.DHG14;
import org.apache.commons.net.ssh.kex.KeyExchange;
import org.apache.commons.net.ssh.keyprovider.FileKeyProvider;
import org.apache.commons.net.ssh.keyprovider.KeyProvider;
import org.apache.commons.net.ssh.keyprovider.OpenSSHKeyFile;
import org.apache.commons.net.ssh.keyprovider.PKCS8KeyFile;
import org.apache.commons.net.ssh.mac.HMACMD5;
import org.apache.commons.net.ssh.mac.HMACMD596;
import org.apache.commons.net.ssh.mac.HMACSHA1;
import org.apache.commons.net.ssh.mac.HMACSHA196;
import org.apache.commons.net.ssh.mac.MAC;
import org.apache.commons.net.ssh.random.BouncyCastleRandom;
import org.apache.commons.net.ssh.random.JCERandom;
import org.apache.commons.net.ssh.random.SingletonRandomFactory;
import org.apache.commons.net.ssh.signature.Signature;
import org.apache.commons.net.ssh.signature.SignatureDSA;
import org.apache.commons.net.ssh.signature.SignatureRSA;
import org.apache.commons.net.ssh.transport.Transport;
import org.apache.commons.net.ssh.userauth.AuthBuilder;
import org.apache.commons.net.ssh.userauth.UserAuthService;
import org.apache.commons.net.ssh.util.KnownHosts;
import org.apache.commons.net.ssh.util.SecurityUtils;

/**
 * Secure Shell client API.
 * <p>
 * The default constructor initializes {@code SSHClient} using {@link #getDefaultFactoryManager()}.
 * Optionally, {@code SSHClient} may be constructed with a {@link FactoryManager} instance that has
 * been initialized with implementations of the requisite algorithms.
 * <p>
 * Before connection is established, host key verification needs to be accounted for. This is done
 * by specifying one or more {@link HostKeyVerifier} objects. Database of known hostname-key pairs
 * in the OpenSSH {@code "known_hosts"} format can be loaded for host key verification.
 * <p>
 * Once connection has been established, user authentication can be completed by obtaining an
 * instance of {@link AuthBuilder}, or using any of the convenience methods provided in this class.
 * <p>
 * Example:
 * <p>
 * 
 * <pre>
 * client = new SSHClient();
 * client.initUserKnownHosts();
 * client.connect(&quot;localhost&quot;);
 * client.authPassword(&quot;username&quot;, &quot;password&quot;);
 * // this is the part that remains ;-) 
 * client.disconnect();
 * </pre>
 * 
 * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
 */
public class SSHClient extends SocketClient
{
    
    /**
     * Creates a {@link FactoryManager} instance with all known (and available) implementations.
     * <p>
     * These are as follows. Italicised items are only available in the presence of <a
     * href="http://www.bouncycastle.org/java.html">BouncyCastle</a> as a properly registered
     * security provider.
     * <ul>
     * <li><b>Key exchange</b>: <i>diffie-hellman-group14-sha1</i>, diffie-hellman-group1-sha1</li>
     * <li><b>Signature</b>: ssh-rsa, ssh-dss</li>
     * <li><b>Cipher</b>: aes128-cbc, aes192-cbc, aes256-cbs, blowfish-cbc, 3des-cbc</li>
     * <li><b>MAC</b>: hmac-sha1, hmac-sha1-96, hmac-md5, hmac-md5-96</li>
     * </ul>
     * 
     * In addition, {@link FileKeyProvider}'s for PKCS and OpenSSH encoded key files are available
     * only in the presence of BouncyCastle.
     * 
     * The BouncyCastle Psuedo-Random Number Generator (PRNG) is set if present, otherwise the JCE
     * PRNG.
     * 
     * @return an initialized {@link FactoryManager}
     */
    @SuppressWarnings("unchecked")
    public static FactoryManager getDefaultFactoryManager()
    {
        FactoryManager fm = new FactoryManager();
        
        if (SecurityUtils.isBouncyCastleRegistered()) {
            fm.setKeyExchangeFactories(Arrays.<NamedFactory<KeyExchange>> asList(new DHG14.Factory(),
                                                                                 new DHG1.Factory()));
            fm.setRandomFactory(new SingletonRandomFactory(new BouncyCastleRandom.Factory()));
            fm.setFileKeyProviderFactories(Arrays.<NamedFactory<FileKeyProvider>> asList(new PKCS8KeyFile.Factory(),
                                                                                         new OpenSSHKeyFile.Factory()));
        } else {
            fm.setKeyExchangeFactories(Arrays.<NamedFactory<KeyExchange>> asList(new DHG1.Factory()));
            fm.setRandomFactory(new SingletonRandomFactory(new JCERandom.Factory()));
            fm.setFileKeyProviderFactories(Arrays.<NamedFactory<FileKeyProvider>> asList()); // empty
        }
        
        List<NamedFactory<Cipher>> avail =
                new LinkedList<NamedFactory<Cipher>>(Arrays.<NamedFactory<Cipher>> asList(new AES128CBC.Factory(),
                                                                                          new AES192CBC.Factory(),
                                                                                          new AES256CBC.Factory(),
                                                                                          new BlowfishCBC.Factory(),
                                                                                          new TripleDESCBC.Factory()));
        for (Iterator<NamedFactory<Cipher>> i = avail.iterator(); i.hasNext();) {
            final NamedFactory<Cipher> f = i.next();
            try {
                final Cipher c = f.create();
                final byte[] key = new byte[c.getBlockSize()];
                final byte[] iv = new byte[c.getIVSize()];
                c.init(Cipher.Mode.Encrypt, key, iv);
            } catch (Exception e) {
                i.remove();
            }
        }
        
        fm.setCipherFactories(avail);
        fm.setCompressionFactories(Arrays.<NamedFactory<Compression>> asList(new CompressionNone.Factory(),
                                                                             new CompressionDelayedZlib.Factory(),
                                                                             new CompressionZlib.Factory()));
        fm.setMACFactories(Arrays.<NamedFactory<MAC>> asList(new HMACSHA1.Factory(), new HMACSHA196.Factory(),
                                                             new HMACMD5.Factory(), new HMACMD596.Factory()));
        fm.setSignatureFactories(Arrays.<NamedFactory<Signature>> asList(new SignatureRSA.Factory(),
                                                                         new SignatureDSA.Factory()));
        
        return fm;
    }
    
    protected final Session trans;
    
    protected final ConnectionService conn;
    
    /**
     * Default constructor
     */
    public SSHClient()
    {
        this(SSHClient.getDefaultFactoryManager());
    }
    
    /**
     * Constructor that allows specifying the {@link FactoryManager}
     * 
     * @param factoryManager
     */
    public SSHClient(FactoryManager factoryManager)
    {
        setDefaultPort(DEFAULT_PORT);
        trans = new Transport(factoryManager);
        conn = new ConnectionProtocol(trans);
    }
    
    /**
     * Add a {@link HostKeyVerifier} whose {@link HostKeyVerifier#verify} method will be invoked for
     * verifying host key during connection establishment.
     * <p>
     * Needless to say, this is only relevant before connection is established.
     * 
     * @param hostKeyVerifier
     */
    public void addHostKeyVerifier(HostKeyVerifier hostKeyVerifier)
    {
        trans.addHostKeyVerifier(hostKeyVerifier);
    }
    
    /**
     * Attempts authentication using the {@code "password"} authentication method.
     * 
     * @param username
     *            the username to authenticate
     * @param password
     *            the {@link PasswordFinder} to use
     * @throws SSHException
     *             if an error occurs during the authentication process
     */
    public void authPassword(String username, PasswordFinder password) throws SSHException
    {
        getAuthBuilder().withUsername(username).authPassword(password).build().authenticate();
    }
    
    /**
     * Attempts authentication using the {@code "password"} authentication method.
     * 
     * @param username
     *            the username to authenticate
     * @param password
     *            the password to use
     * @throws SSHException
     *             if an error occurs during the authentication process
     */
    public void authPassword(String username, String password) throws SSHException
    {
        getAuthBuilder().withUsername(username).authPassword(password).build().authenticate();
    }
    
    /**
     * Attempts authentication using the {@code "publickey"} authentication method.
     * <p>
     * The {@code keyProvider} argument may be an instance of {@link FileKeyProvider} that is
     * created using any of the convenience methods provided in this class.
     * 
     * @param username
     *            the username to authenticate
     * @param keyProvider
     *            the {@link KeyProvider} for private key
     * @throws SSHException
     */
    public void authPublickey(String username, KeyProvider keyProvider) throws SSHException
    {
        getAuthBuilder().withUsername(username).authPublickey(keyProvider).build().authenticate();
    }
    
    @Override
    public void disconnect() throws IOException
    {
        trans.disconnect();
        super.disconnect();
    }
    
    /**
     * Returns an instance of {@link AuthBuilder} which can be used to build an instance of
     * {@link UserAuthService} and authenticate using that.
     */
    public AuthBuilder getAuthBuilder()
    {
        return new AuthBuilder(trans, conn, System.getProperty("user.name"));
    }
    
    /**
     * Returns the associated {@link Session} instance.
     */
    public Session getSession()
    {
        return trans;
    }
    
    /**
     * 
     * Creates {@link KnownHosts} objects from the specified locations.
     * 
     * @param locations
     *            one or more locations for {@code known_hosts} files
     * @throws IOException
     *             if there is an error loading from any of these locations
     */
    public void initKnownHosts(String... locations) throws IOException
    {
        for (String loc : locations)
            trans.addHostKeyVerifier(new KnownHosts(loc));
    }
    
    /**
     * Attempts loading the user's {@code known_hosts} file from the default location, i.e. {@code
     * ~/.ssh/known_hosts} and {@code ~/.ssh/known_hosts2} on most platforms.
     * <p>
     * {@link #initKnownHosts(String...)} is a more generic method.
     * 
     * @throws IOException
     *             if there is an error loading from <b>both</b> locations
     */
    public void initUserKnownHosts() throws IOException
    {
        String homeDir = System.getProperty("user.home");
        boolean a = false, b = false;
        if (homeDir != null) {
            String kh = homeDir + File.separator + ".ssh" + File.separator + "known_hosts";
            try {
                initKnownHosts(kh); // "~/.ssh/known_hosts" 
            } catch (IOException ignored) {
                a = true;
            }
            try {
                initKnownHosts(kh + "2"); // "~/.ssh/known_hosts2" 
            } catch (IOException ignored) {
                b = true;
            }
        }
        if (a && b)
            throw new IOException("Could not load user known_hosts");
    }
    
    @Override
    public boolean isConnected()
    {
        return super.isConnected() && trans.isRunning();
    }
    
    /**
     * Convenience method for creating a {@link FileKeyProvider} instance from a location where the
     * key file is located.
     * 
     * @param location
     *            the location for the key file
     * @return the {@link FileKeyProvider} intialized with given location
     * @throws IOException
     *             if the key file format is not known, if the file could not be read, etc.
     */
    public FileKeyProvider loadKeyFile(String location) throws IOException
    {
        return loadKeyFile(location, "");
    }
    
    /**
     * Convenience method for creating a {@link FileKeyProvider} instance from a location where an
     * <i>encrypted</i> key file is located.
     * 
     * @param location
     *            the location of the key file
     * @param pwdf
     *            the {@link PasswordFinder} that can supply the passphrase for decryption
     * @return the {@link FileKeyProvider} initialized with given location
     * @throws IOException
     *             if the key file format is not known, if the file could not be read, etc.
     */
    public FileKeyProvider loadKeyFile(String location, PasswordFinder pwdf) throws IOException
    {
        String format = SecurityUtils.detectKeyFileFormat(location);
        if (format.equals("unknown"))
            throw new IOException("Unknown key file format");
        FileKeyProvider fkp =
                NamedFactory.Utils.create(trans.getFactoryManager().getFileKeyProviderFactories(), format);
        fkp.init(location, pwdf);
        return fkp;
    }
    
    /**
     * Convenience method for creating a {@link FileKeyProvider} instance from a location where an
     * <i>encrypted</i> key file is located.
     * 
     * @param location
     *            the location of the key file
     * @param passphrase
     *            the passphrase for unlocking the key
     * @return the {@link FileKeyProvider} initialized with given location
     * @throws IOException
     *             if the key file format is not known, if the file could not be read etc.
     */
    public FileKeyProvider loadKeyFile(String location, String passphrase) throws IOException
    {
        return loadKeyFile(location, PasswordFinder.Util.createOneOff(passphrase));
    }
    
    /**
     * On connection establishment, also initialize the SSH transport via {@link Session#init}
     */
    @Override
    protected void _connectAction_() throws IOException
    {
        super._connectAction_();
        trans.init(_socket_);
    }
    
}
