package org.apache.commons.net.ssh.util;

import org.slf4j.Logger;

public class StateMachine<S, T extends Throwable>
{
    
    private final Logger log;
    private final Object lock;
    private final FriendlyChainer<T> chainer;
    
    private Thread awaiter;
    private Throwable queuedEx;
    
    private S current; // current state
    
    public StateMachine(Logger log, Object lock, FriendlyChainer<T> chainer)
    {
        assert log != null && lock != null && chainer != null;
        this.log = log;
        this.lock = lock;
        this.chainer = chainer;
    }
    
    public void await(S s) throws T
    {
        synchronized (lock) {
            
            awaiter = Thread.currentThread(); // So that our spin on interrupt knows which thread to interrupt
            try {
                while (current != s)
                    lock.wait();
            } catch (InterruptedException signal) {
                log.error("Got interrupted while waiting for {} due to {}", s, queuedEx.toString());
                Thread.interrupted(); // Clear interrupted status
                throw chainer.chain(queuedEx);
            } finally {
                awaiter = null;
            }
            
            log.debug("Woke up to {}", current);
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
        synchronized (lock) {
            if (awaiter != null) {
                queuedEx = t;
                awaiter.interrupt();
            }
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
