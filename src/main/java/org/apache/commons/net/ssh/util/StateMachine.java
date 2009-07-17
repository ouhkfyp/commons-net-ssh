package org.apache.commons.net.ssh.util;

import org.slf4j.Logger;

public class StateMachine<State, Exc extends Throwable>
{
    
    private final Logger log;
    
    /** Object on which this instance synchronizes */
    private final Object lock;
    
    /** Our friendly exception chainer */
    private final FriendlyChainer<Exc> chainer;
    
    /** Current state */
    private State current;
    /** A thread currently engaged in lock.wait() */
    private Thread awaiter;
    /** A queued exception */
    private Throwable queuedEx;
    
    public StateMachine(Logger log, Object lock, FriendlyChainer<Exc> chainer)
    {
        assert log != null && lock != null && chainer != null;
        this.log = log;
        this.lock = lock;
        this.chainer = chainer;
    }
    
    public void assertIn(State... state) throws Exc
    {
        if (notIn(state))
            throw chainer.chain(new AssertionError());
    }
    
    public void await(State s) throws Exc
    {
        synchronized (lock) {
            
            // So that our spin on interruption knows which thread to interrupt
            awaiter = Thread.currentThread();
            
            try {
                while (current != s)
                    lock.wait();
            } catch (InterruptedException signal) {
                log.error("Got interrupted while waiting for {} due to {}", s, queuedEx.toString());
                Thread.interrupted(); // Clear interrupted status
                throw chainer.chain(queuedEx);
            } finally {
                // End of interruptible context 
                awaiter = null;
            }
            
            log.debug("Woke up to {}", current);
        }
    }
    
    public State current()
    {
        synchronized (lock) {
            return current;
        }
    }
    
    public boolean in(State... states)
    {
        synchronized (lock) {
            boolean res = false;
            for (State s : states)
                res |= current == s;
            return res;
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
    
    public boolean notIn(State... states)
    {
        synchronized (lock) {
            return !in(states);
        }
    }
    
    public void transition(State newState)
    {
        synchronized (lock) {
            log.debug("Changing state  [ {} -> {} ]", current, newState);
            current = newState;
            lock.notifyAll();
        }
    }
    
}
