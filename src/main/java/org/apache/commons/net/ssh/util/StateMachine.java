package org.apache.commons.net.ssh.util;

import org.slf4j.Logger;

public class StateMachine<S, T extends Throwable>
{
    
    private final Logger log;
    private final Object lock;
    private final FriendlyChainer<T> chainer;
    
    private Thread awaiter;
    private Throwable queued;
    
    private S current; // current state
    
    public StateMachine(Logger log, Object lock, FriendlyChainer<T> chainer)
    {
        this.log = log;
        this.lock = lock != null ? lock : this;
        this.chainer = chainer;
    }
    
    public boolean await(S s) throws T
    {
        synchronized (lock) {
            // So that our spin on interrupt knows which thread to interrupt
            awaiter = Thread.currentThread();
            try {
                while (current != s)
                    lock.wait();
            } catch (InterruptedException e) {
                log.error("Got interrupted while waiting for {}", s);
                Thread.interrupted(); // Clear interrupted status
                throw chainer.chain(queued != null ? queued : e);
            } finally {
                awaiter = null;
            }
            log.debug("Woke up to {}", current);
            return true;
        }
    }
    
    public S current()
    {
        synchronized (lock) {
            return current;
        }
    }
    
    public boolean in(S... states)
    {
        synchronized (lock) {
            boolean flag = false;
            for (S s : states)
                flag |= current == s;
            return flag;
        }
    }
    
    public void interrupt(Throwable t)
    {
        queued = t;
        synchronized (lock) {
            if (awaiter != null)
                awaiter.interrupt();
        }
    }
    
    public boolean notIn(S... states)
    {
        synchronized (lock) {
            return !in(states);
        }
    }
    
    public void transition(S newState)
    {
        synchronized (lock) {
            current = newState;
            lock.notifyAll();
        }
    }
    
}
