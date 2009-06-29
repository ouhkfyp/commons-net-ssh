package org.apache.commons.net.ssh.userauth;

import java.io.IOException;

import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.util.LanguageQualifiedString;

public interface UserAuthService extends Service
{
    
    interface Builder
    {
        
        UserAuthService build();
        
        Builder withNextService(Service nextService);
        
        Builder withUsername(String username);
        
    }
    
    // same as org.bouncycastle.openssl.PasswordFinder
    interface PasswordFinder
    {
        char[] getPassword();
    }
    
    String NAME = "ssh-userauth";
    
    void authenticate() throws IOException;
    
    LanguageQualifiedString getBanner();
    
}
