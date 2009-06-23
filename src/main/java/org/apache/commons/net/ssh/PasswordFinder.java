package org.apache.commons.net.ssh;

/**
 * Same as org.bouncycastle.openssl.PasswordFinder; offers a sole method for password retrieval.
 * 
 * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
 */
public interface PasswordFinder
{
    
    char[] getPassword();
    
}
