package org.apache.commons.net.ssh.util;

public interface FriendlyChainer<Z extends Throwable>
{
    
    Z chain(Throwable t);
    
}