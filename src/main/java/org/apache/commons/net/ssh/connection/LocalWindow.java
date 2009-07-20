package org.apache.commons.net.ssh.connection;

import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Constants.Message;

public class LocalWindow extends Window
{
    
    private final Channel chan;
    
    public LocalWindow(Channel chan)
    {
        this.chan = chan;
    }
    
    public synchronized void consumeAndCheck(int howmuch) throws TransportException
    {
        consume(howmuch);
        
    }
    
    protected void check(int max) throws TransportException
    {
        int threshold = Math.min(maxPacketSize * 8, max / 4);
        
        if (max - size > maxPacketSize && (max - size > threshold || size < threshold)) {
            
            if (log.isDebugEnabled())
                log.debug("Increasing by " + (max - size) + " up to " + max);
            
            sendWindowAdjust(max - size);
            
            size = max;
        }
    }
    
    protected void sendWindowAdjust(int inc) throws TransportException
    {
        chan.getTransport().writePacket(new Buffer(Message.CHANNEL_WINDOW_ADJUST) //
                                                                                 .putInt(chan.getRecipient()) //
                                                                                 .putInt(inc));
    }
    
}
