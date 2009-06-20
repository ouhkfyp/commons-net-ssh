package org.apache.commons.net.ssh;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public interface Session
{
    
    void init(InputStream input, OutputStream output) throws IOException;
    
    void disconnect(int code, String message) throws IOException;
    
}
