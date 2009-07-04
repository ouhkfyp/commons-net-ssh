package org.apache.commons.net.ssh;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractService implements Service
{
    
    protected final Logger log = LoggerFactory.getLogger(getClass());
    protected final Session session;
    
    protected volatile Thread currentThread;
    protected volatile SSHException exception;
    
    public AbstractService(Session session)
    {
        this.session = session;
    }
    
    public Session getSession()
    {
        return session;
    }
    
    public void notifyError(SSHException exception)
    {
        this.exception = exception;
        if (currentThread != null && shouldInterrupt())
            currentThread.interrupt();
    }
    
    public void request() throws TransportException
    {
        Service active = session.getService();
        if (!equals(active))
            if (active != null && getName().equals(active.getName()))
                session.setService(this);
            else
                session.reqService(this);
    }
    
    protected void enterInterruptibleContext()
    {
        currentThread = Thread.currentThread();
    }
    
    protected void leaveInterruptibleContext()
    {
        currentThread = null;
    }
    
    protected abstract boolean shouldInterrupt();
    
}
