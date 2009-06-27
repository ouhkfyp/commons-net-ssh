package org.apache.commons.net.ssh.userauth;

import java.io.IOException;

import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.util.LanguageQualifiedString;

public interface UserAuthService extends Service
{
    
    interface PasswordFinder
    {
        char[] getPassword();
    }
    
    String NAME = "ssh-userauth";
    
    void authenticate() throws IOException;
    
    LanguageQualifiedString getBanner();
    
}
