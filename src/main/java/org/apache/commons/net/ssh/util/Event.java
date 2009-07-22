package org.apache.commons.net.ssh.util;

import java.util.concurrent.locks.ReentrantLock;

/*
 * Syntactic sugar around Future
 */
public class Event<Ex extends Throwable> extends Future<Boolean, Ex>
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
            Future.Util.<Boolean, T> notifyError(error, events);
        }
        
        public static <T extends Throwable> void notifyError(Throwable error, Iterable<Event<T>> events)
        {
            Future.Util.<Boolean, T> notifyError(error, events);
        }
    }
    
    public Event(String name, FriendlyChainer<Ex> chainer)
    {
        super(name, chainer, null);
    }
    
    public Event(String name, FriendlyChainer<Ex> chainer, ReentrantLock lock)
    {
        super(name, chainer, lock);
    }
    
    public void await() throws Ex
    {
        super.get();
    }
    
    public void await(int timeout) throws Ex
    {
        super.get(timeout);
    }
    
    public void set()
    {
        super.set(true);
    }
    
}
