package org.apache.commons.net.ssh.util;

public class All
{
    
    public static final boolean notNull(Object... all)
    {
        for (Object x : all)
            if (x == null)
                return false;
        return true;
    }
    
}
