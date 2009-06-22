package org.apache.commons.net.ssh.userauth;

import java.io.IOException;

import org.apache.commons.net.ssh.util.Buffer;

public class Password implements Method
{
    
    private String username;
    private char[] password;
    
    Password(String username, char[] password)
    {
        this.username = username;
        this.password = password;
    }
    
    public String[] getAllowedMethods()
    {
        // TODO Auto-generated method stub
        return null;
    }

    public Result next(Buffer buffer) throws IOException
    {
        // TODO Auto-generated method stub
        return null;
    }
    
}
