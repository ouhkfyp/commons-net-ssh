package org.apache.commons.net.ssh.connection;

import java.io.InputStream;
import java.io.OutputStream;

public interface IO
{
    
    InputStream getInputStream();
    
    OutputStream getOutputStream();
    
}
