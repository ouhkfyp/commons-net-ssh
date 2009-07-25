package org.apache.commons.net.ssh.connection;

import org.apache.commons.net.ssh.transport.TransportException;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Constants.Message;

public abstract class AbstractDirectChannel extends AbstractChannel
{
    
    protected AbstractDirectChannel(ConnectionService conn)
    {
        super(conn);
        conn.attach(this);
    }
    
    public void open() throws ConnectionException, TransportException
    {
        lock.lock();
        try {
            if (!init.isSet()) {
                trans.writePacket(buildOpenReq());
                init.await(conn.getTimeout());
            }
        } finally {
            lock.unlock();
        }
    }
    
    protected Buffer buildOpenReq()
    {
        return new Buffer(Message.CHANNEL_OPEN) //
                                               .putString(getType()) //
                                               .putInt(id) //
                                               .putInt(localWin.getSize()) //
                                               .putInt(localWin.getMaxPacketSize());
    }
    
    @Override
    protected void gotUnknown(Message cmd, Buffer buf) throws TransportException
    {
        switch (cmd)
        {
            case CHANNEL_OPEN_CONFIRMATION:
            {
                init(buf);
                break;
            }
            case CHANNEL_OPEN_FAILURE:
            {
                init.error(new OpenFailException(getType(), buf.getInt(), buf.getString()));
                conn.forget(this);
                break;
            }
            default:
                super.gotUnknown(cmd, buf);
        }
    }
    
}
