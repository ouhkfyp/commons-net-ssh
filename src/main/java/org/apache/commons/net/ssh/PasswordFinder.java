package org.apache.commons.net.ssh;

/**
 * Same as BouncyCastle's PasswordFinder
 * 
 */
public interface PasswordFinder
{
    
    char[] getPassword();
    
}
