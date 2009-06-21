/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.commons.net.ssh.transport;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.security.PublicKey;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.TimeUnit;

import org.apache.commons.net.ssh.FactoryManager;
import org.apache.commons.net.ssh.SSHConstants;
import org.apache.commons.net.ssh.SSHException;
import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.Session;
import org.apache.commons.net.ssh.random.Random;
import org.apache.commons.net.ssh.util.Buffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Transport layer
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
 */
public class Transport implements Session
{
    
    /*
     * This enum describes what 'phase' this SSH session is in, so we that we know which class to delegate message
     * handling to, can wait for some phase to be reached, etc.
     */
    private enum State
    {
        KEX, // delegate message handling to Kex
        KEX_DONE, // indicates kex done
        SERVICE_REQ, // a service has been requested
        SERVICE_OK, // indicates service request was successful
        SERVICE, // delegate message handling to the active service 
        ERROR, // indicates an error event in one of the threads
        STOPPED, //indicates this session has been stopped
    }
    
    private State state;
    
    private final Logger log = LoggerFactory.getLogger(getClass());
    
    private final FactoryManager fm;
    
    final Random prng;
    
    private final KexHandler kex;
    
    final EncDec bin;
    
    /*
     * Outgoing data is put here. Since it is a SynchronousQueue, until outPump is interested in taking, putting an item
     * blocks.
     */
    private final SynchronousQueue<byte[]> outQ = new SynchronousQueue<byte[]>();
    
    /*
     * If an error occurs in one of the threads spawned by this class, it is set in this field.
     */
    private Exception exception;
    
    /* Lock object for session phase */
    private final Object stateLock = new Object();
    
    /* Lock object supporting correct encoding and queuing of packets */
    private final Object encodeLock = new Object();
    
    // private final ReentrantLock lock = new ReentrantLock();
    
    private InputStream input;
    private OutputStream output;
    
    /*
     * This thread reads data from the input stream, putting it into decodeBuffer. Packets are decoded and handled.
     */
    private final Thread inPump = new Thread() {
        @Override
        public void run()
        {
            while (!stopPumping)
                try
                {
                    bin.gotByte((byte) input.read());
                } catch (Exception e)
                {
                    if (!stopPumping)
                        setError(e);
                }
            log.debug("Stopping");
        }
    };
    
    /*
     * This thread takes byte[] from outQ and sends it over the output stream for this session.
     */
    private final Thread outPump = new Thread() {
        @Override
        public void run()
        {
            while (!stopPumping)
                try
                {
                    output.write(outQ.take());
                } catch (Exception e)
                {
                    log.error("Encountered error: {}", e.toString());
                    if (!stopPumping)
                        setError(e);
                }
            log.debug("Stopping");
        }
    };
    
    /* true value tells inPump and outPump to stop */
    private volatile boolean stopPumping = false;
    
    private Service service; // currently active service i.e. ssh-userauth, ssh-connection
    
    boolean authed = false;
    
    /* Client version identification string */
    private String clientVersion;
    
    /* Server version identification string */
    private String serverVersion;
    
    public Transport(FactoryManager factoryManager)
    {
        super();
        
        fm = factoryManager;
        prng = factoryManager.getRandomFactory().create();
        bin = new EncDec(this);
        kex = new KexHandler(this);
        
        inPump.setName("inPump");
        inPump.setDaemon(true);
        outPump.setName("outPump");
        outPump.setDaemon(true);
    }
    
    public Buffer createBuffer(SSHConstants.Message cmd)
    {
        Buffer buffer = new Buffer();
        buffer.rpos(5);
        buffer.wpos(5);
        buffer.putByte(cmd.toByte());
        return buffer;
    }
    
    public void disconnect(int reason, String msg) throws IOException
    {
        log.debug("Sending SSH_MSG_DISCONNECT: reason=[{}], msg=[{}]", reason, msg);
        Buffer buffer = createBuffer(SSHConstants.Message.SSH_MSG_DISCONNECT);
        buffer.putInt(reason);
        buffer.putString(msg);
        buffer.putString("");
        writePacket(buffer);
        stop();
    }
    
    public String getClientVersion()
    {
        return clientVersion;
    }
    
    public FactoryManager getFactoryManager()
    {
        return fm;
    }
        
    public String getServerVersion()
    {
        return serverVersion;
    }
    
    public void init(InputStream input, OutputStream output) throws Exception
    {
        this.input = input;
        this.output = output;
        
        clientVersion = "SSH-2.0-" + fm.getVersion();
        log.info("Client version string: {}", clientVersion);
        output.write((clientVersion + "\r\n").getBytes());
        
        Buffer buf = new Buffer();
        while ((serverVersion = readIdentification(buf)) == null)
            buf.putByte((byte) input.read());
        log.info("Server version string: {}", serverVersion);
        
        setState(State.KEX);
        
        outPump.start();
        inPump.start();
        
        kex.init();
        
        waitFor(State.KEX_DONE);
        
    }

    public boolean isRunning()
    {
        return !(state == State.ERROR || state == State.STOPPED);
    }
    
    public void startService(Service service) throws Exception
    {
        log.info("Setting active service to {}", service.getName());
        this.service = service;
        setState(State.SERVICE_REQ);
        sendServiceRequest(service.getName());
        waitFor(State.SERVICE_OK);
    }
    
    boolean verifyHost(PublicKey key)
    {
        // TODO: verify host key!! -- PRIORITY
        return true;
    }
    
    public int writePacket(Buffer payload) throws IOException
    {
        int seq = 0;
        /*
         * Synchronize all write requests as needed by the encoding algorithm and also queue the write request in this
         * synchronized block to ensure packets are sent in the correct order.
         */
        synchronized (encodeLock)
        {
            seq = bin.encode(payload);
            byte[] data = payload.getCompactData();
            try
            {
                while (!outQ.offer(data, 1L, TimeUnit.SECONDS))
                    if (!outPump.isAlive())
                        throw new IOException("Output pumping thread is dead");
            } catch (InterruptedException e)
            {
                InterruptedIOException ioe = new InterruptedIOException();
                ioe.initCause(e);
                throw ioe;
            }
        }
        return seq;
    }
    
    private String readIdentification(Buffer buffer) throws IOException
    {
        String serverVersion;
        
        byte[] data = new byte[256];
        for (;;)
        {
            int rpos = buffer.rpos();
            int pos = 0;
            boolean needLf = false;
            for (;;)
            {
                if (buffer.available() == 0)
                {
                    // need more data, so undo reading and return null
                    buffer.rpos(rpos);
                    return null;
                }
                byte b = buffer.getByte();
                if (b == '\r')
                {
                    needLf = true;
                    continue;
                }
                if (b == '\n')
                    break;
                if (needLf)
                    throw new IllegalStateException("Incorrect identification: bad line ending");
                if (pos >= data.length)
                    throw new IllegalStateException("Incorrect identification: line too long");
                data[pos++] = b;
            }
            serverVersion = new String(data, 0, pos);
            if (serverVersion.startsWith("SSH-"))
                break;
            if (buffer.rpos() > 16 * 1024)
                throw new IllegalStateException("Incorrect identification: too many header lines");
        }
        
        if (!serverVersion.startsWith("SSH-2.0-"))
            throw new SSHException(SSHConstants.SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED);
        
        return serverVersion;
    }
    
    private void sendServiceRequest(String serviceName) throws IOException
    {
        log.info("Sending SSH_MSG_SERVICE_REQUEST for {}", serviceName);
        Buffer buffer = createBuffer(SSHConstants.Message.SSH_MSG_SERVICE_REQUEST);
        buffer.putString(serviceName);
        writePacket(buffer);
    }
    
    /**
     * Used by inPump and outPump to notify of an error, since it would otherwise escape unnoticed
     * 
     * @param e
     *            Exception
     */
    private void setError(Exception e)
    {
        exception = e;
        log.error("Encountered error: {}", e);
        
        // Future TODO: notify active service
        
        /*
         * will result in exception being thrown in any thread that was waiting for state change; see waitFor()
         */
        setState(State.ERROR);
        
        stop(); // stop inPump and outPump
    }
    
    /**
     * Block for specified state.
     * 
     * @param s
     *            State
     * @throws Exception
     *             in case of error event while waiting
     */
    private void waitFor(State s) throws Exception
    {
        synchronized (stateLock)
        {
            while (state != s && state != State.ERROR && state != State.STOPPED)
                try
                {
                    stateLock.wait(0);
                } catch (InterruptedException e)
                {
                    throw e;
                }
        }
        log.debug("Woke up to {}", state.toString());
        if (state != s)
            if (state == State.ERROR)
                throw exception;
            else if (state == State.STOPPED)
                throw new SSHException("Stopped");
    }
    
    void handle(Buffer packet) throws Exception
    {
        SSHConstants.Message cmd = packet.getCommand();
        log.debug("Received packet {}", cmd);
        switch (cmd)
        {
            case SSH_MSG_DISCONNECT:
            {
                int code = packet.getInt();
                String msg = packet.getString();
                log.info("Received SSH_MSG_DISCONNECT (reason={}, msg={})", code, msg);
                throw new SSHException(code, msg);
            }
            case SSH_MSG_UNIMPLEMENTED:
            {
                int code = packet.getInt();
                log.info("Received SSH_MSG_UNIMPLEMENTED #{}", code);
                break;
            }
            case SSH_MSG_DEBUG:
            {
                boolean display = packet.getBoolean();
                String msg = packet.getString();
                log.info("Received SSH_MSG_DEBUG (display={}) '{}'", display, msg);
                break;
            }
            case SSH_MSG_IGNORE:
            {
                log.info("Received SSH_MSG_IGNORE");
                break;
            }
            default:
            {
                switch (state)
                {
                    case KEX:
                    {
                        if (kex.handle(cmd, packet)) // key-exchange completed
                            setState(State.KEX_DONE);
                        break;
                    }
                    case SERVICE_REQ:
                    {
                        if (cmd != SSHConstants.Message.SSH_MSG_SERVICE_ACCEPT)
                        {
                            disconnect(SSHConstants.SSH_DISCONNECT_PROTOCOL_ERROR,
                                       "Protocol error: expected packet SSH_MSG_SERVICE_ACCEPT, got " + cmd);
                            return;
                        }
                        setState(State.SERVICE_OK);
                        break;
                    }
                    case SERVICE:
                    {
                        if (cmd != SSHConstants.Message.SSH_MSG_KEXINIT)
                            service.handle(cmd, packet);
                        else
                        {
                            /*
                             * Key re-exchange. Per RFC should be after every GB or 1 hour, whichever is sooner. ---
                             * TODO: ?initiate?
                             */
                            setState(State.KEX);
                            kex.handle(cmd, packet);
                        }
                        break;
                    }
                    case KEX_DONE:
                    case SERVICE_OK:
                        // in-between states: what happens here??
                        break;
                    default:
                        assert false;
                }
            }
        }
    }
    
    /**
     * Send an unimplemented packet. This packet should contain the sequence id of the unsupported packet.
     * 
     * @throws IOException
     *             if an error occured sending the packet
     */
    void sendNotImplemented(int num) throws IOException
    {
        Buffer buffer = createBuffer(SSHConstants.Message.SSH_MSG_UNIMPLEMENTED);
        buffer.putInt(num);
        writePacket(buffer);
    }
    
    /* (non-Javadoc)
     * @see org.apache.commons.net.ssh.transport.Service#setAuthenticated(boolean)
     */
    public void setAuthenticated(boolean authed)
    {
        this.authed = authed;
    }
    
    void setState(State newState)
    {
        log.debug("Changing state  [ {} -> {} ]", state, newState);
        synchronized (stateLock)
        {
            state = newState;
            stateLock.notifyAll();
        }
    }
    
    void stop()
    {
        // stop inPump and outPump
        stopPumping = true;
        while (inPump.isAlive() || outPump.isAlive())
            ;
        
        // will wakeup any thread that was waiting for phase change, see waitFor()
        setState(State.STOPPED);
        
        // can safely reset these refs
        input = null;
        output = null;
    }
    
}
