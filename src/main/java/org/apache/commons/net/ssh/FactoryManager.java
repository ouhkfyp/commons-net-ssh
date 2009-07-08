package org.apache.commons.net.ssh;

import java.util.List;

import org.apache.commons.net.ssh.cipher.Cipher;
import org.apache.commons.net.ssh.compression.Compression;
import org.apache.commons.net.ssh.kex.KeyExchange;
import org.apache.commons.net.ssh.keyprovider.FileKeyProvider;
import org.apache.commons.net.ssh.mac.MAC;
import org.apache.commons.net.ssh.random.Random;
import org.apache.commons.net.ssh.signature.Signature;

/**
 * Container class for {@link NamedFactory} implementations of {@link KeyExchange}, {@link Cipher},
 * {@link Compression}, {@link MAC}, {@link Signature}, {@link Random}, and {@link FileKeyProvider}.
 * <p>
 * This class is used in {@link Session} initialization.
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
 */
public class FactoryManager
{
    
    private List<NamedFactory<KeyExchange>> keyExchangeFactories;
    private List<NamedFactory<Cipher>> cipherFactories;
    private List<NamedFactory<Compression>> compressionFactories;
    private List<NamedFactory<MAC>> macFactories;
    private List<NamedFactory<Signature>> signatureFactories;
    private List<NamedFactory<FileKeyProvider>> fileKeyProviderFactories;
    private NamedFactory<Random> randomFactory;
    
    /**
     * Retrieve the list of named factories for <code>Cipher</code>.
     * 
     * @return a list of named <code>Cipher</code> factories, never {@code null}
     */
    public List<NamedFactory<Cipher>> getCipherFactories()
    {
        return cipherFactories;
    }
    
    /**
     * Retrieve the list of named factories for <code>Compression</code>.
     * 
     * @return a list of named {@code Compression} factories, never {@code null}
     */
    public List<NamedFactory<Compression>> getCompressionFactories()
    {
        return compressionFactories;
    }
    
    /**
     * Retrieve the list of named factories for {@code FileKeyProvider}.
     * 
     * @return a list of named {@code FileKeyProvider} factories
     */
    public List<NamedFactory<FileKeyProvider>> getFileKeyProviderFactories()
    {
        return fileKeyProviderFactories;
    }
    
    /**
     * Retrieve the list of named factories for <code>KeyExchange</code>.
     * 
     * @return a list of named <code>KeyExchange</code> factories, never {@code null}
     */
    public List<NamedFactory<KeyExchange>> getKeyExchangeFactories()
    {
        return keyExchangeFactories;
    }
    
    /**
     * Retrieve the list of named factories for <code>MAC</code>.
     * 
     * @return a list of named <code>Mac</code> factories, never {@code null}
     */
    public List<NamedFactory<MAC>> getMACFactories()
    {
        return macFactories;
    }
    
    /**
     * Retrieve the {@link Random} factory to be used.
     * 
     * @return the {@link Random} factory, never {@code null}
     */
    public NamedFactory<Random> getRandomFactory()
    {
        return randomFactory;
    }
    
    /**
     * Retrieve the list of named factories for {@link Signature}
     * 
     * @return a list of named {@link Signature} factories, never {@code null}
     */
    public List<NamedFactory<Signature>> getSignatureFactories()
    {
        return signatureFactories;
    }
    
    /**
     * Specify the list of named factories for {@link Cipher}
     * 
     * @param cipherFactories
     */
    public void setCipherFactories(List<NamedFactory<Cipher>> cipherFactories)
    {
        this.cipherFactories = cipherFactories;
    }
    
    /**
     * Specify the list of named factories for
     * 
     * @param compressionFactories
     */
    public void setCompressionFactories(List<NamedFactory<Compression>> compressionFactories)
    {
        this.compressionFactories = compressionFactories;
    }
    
    public void setFileKeyProviderFactories(List<NamedFactory<FileKeyProvider>> fileKeyProviderFactories)
    {
        this.fileKeyProviderFactories = fileKeyProviderFactories;
    }
    
    public void setKeyExchangeFactories(List<NamedFactory<KeyExchange>> keyExchangeFactories)
    {
        this.keyExchangeFactories = keyExchangeFactories;
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
