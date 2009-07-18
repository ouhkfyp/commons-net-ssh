package org.apache.commons.net.ssh.util;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class Event<T extends Throwable>
{
    
    public static class EventException extends Exception
    {
        public EventException(String message)
        {
            super(message);
        }
    }
    
    public static class Util
    {
        
        public static <T extends Throwable> void notifyError(Throwable error, Event<T>... events)
        {
            for (Event<T> event : events)
                event.error(error);
        }
        
        public static <T extends Throwable> void notifyError(Throwable error, Iterable<Event<T>> events)
        {
            for (Event<T> event : events)
                event.error(error);
        }
        
    }
    
    private final String name;
    private final FriendlyChainer<T> chainer;
    private final Lock lock;
    private final Condition cond;
    
    private boolean flag;
    private T pendingEx;
    
    public Event(String name, FriendlyChainer<T> chainer)
    {
        this(name, chainer, null);
    }
    
    public Event(String name, FriendlyChainer<T> chainer, Lock lock)
    {
        this.name = "<< " + name + " >>";
        this.chainer = chainer;
        this.lock = lock == null ? new ReentrantLock() : lock;
        this.cond = this.lock.newCondition();
    }
    
    public void await() throws T
    {
        await(0);
    }
    
    public void await(float seconds) throws T
    {
        lock.lock();
        try {
            if (flag)
                return;
            if (pendingEx != null)
                throw pendingEx;
            
            while (!flag && pendingEx == null)
                if (seconds == 0)
                    cond.await();
                else if (!cond.await((int) (seconds * 1000), TimeUnit.MILLISECONDS))
                    chainer.chain(new EventException("Timeout expired"));
            if (pendingEx != null)
                throw pendingEx;
        } catch (InterruptedException ie) {
            throw chainer.chain(ie);
        } finally {
            lock.unlock();
        }
    }
    
    public void clear()
    {
        lock.lock();
        try {
            pendingEx = null;
            flag = false;
            cond.signalAll();
        } finally {
            lock.unlock();
        }
    }
    
    public void error(String message)
    {
        error(new EventException(message));
    }
    
    public void error(Throwable t)
    {
        lock.lock();
        try {
            pendingEx = chainer.chain(t);
            cond.signalAll();
        } finally {
            lock.unlock();
        }
    }
    
    public boolean isSet()
    {
        lock.lock();
        try {
            return flag;
        } finally {
            lock.unlock();
        }
    }
    
    public void raise(String message) throws T
    {
        lock.lock();
        try {
            error(message);
            throw pendingEx;
        } finally {
            lock.unlock();
        }
    }
    
    public void raise(Throwable t) throws T
    {
        lock.lock();
        try {
            error(t);
            throw pendingEx;
        } finally {
            lock.unlock();
        }
    }
    
    public void set()
    {
        lock.lock();
        try {
            flag = true;
            cond.signalAll();
        } finally {
            lock.unlock();
        }
    }
    
    @Override
    public String toString()
    {
        return name;
    }
    
}
