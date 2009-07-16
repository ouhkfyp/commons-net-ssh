/*
 * Licensed to the Apache Software Founation (ASF) under one
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

import static org.apache.commons.net.ssh.util.Constants.VERSION;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.security.PublicKey;
import java.util.LinkedList;
import java.util.Queue;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.commons.net.ssh.FactoryManager;
import org.apache.commons.net.ssh.HostKeyVerifier;
import org.apache.commons.net.ssh.SSHException;
import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.random.Random;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.StateMachine;
import org.apache.commons.net.ssh.util.Constants.DisconnectReason;
import org.apache.commons.net.ssh.util.Constants.Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Thread-safe {@link Transport} implementation.
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
 */
public class TransportProtocol implements Transport
{
    
    /*
     * This enum describes what state this SSH session is in, so we that we know which class to
     * delegate message handling to, can wait for some state to be reached, etc.
     */
    private enum State
    {
        KEX, // delegate message handling to Negotiator
        KEX_DONE, // indicates kex done
        SERVICE_REQ, // a service has been requested
        SERVICE, // service request was successful; delegate handling to active service
        DEAD, // indicates this session has terminated, _possibly_ because of an error
    }
    
    private final Logger log = LoggerFactory.getLogger(getClass());
    private final StateMachine<State, TransportException> sm =
            new StateMachine<State, TransportException>(log, this, TransportException.chainer);
    
    private final FactoryManager fm;
    
    //    /**
    //     * This field is set if we died because of an error
    //     */
    //    private SSHException causeOfDeath;
    //    
    /** Currently active service i.e. ssh-userauth, ssh-connection */
    private Service service;
    
    private Socket socket;
    private InputStream input;
    private OutputStream output;
    
    /**
     * {@link HostKeyVerifier#verify(InetAddress, PublicKey)} is invoked by
     * {@link #verifyHost(PublicKey)} when we are ready to verify the the server's host key.
     */
    private final Queue<HostKeyVerifier> hostVerifiers = new LinkedList<HostKeyVerifier>();
    
    /** For key (re)exchange */
    private final Negotiator negotiator;
    
    /** Message identifier for last packet received */
    private Message cmd;
    
    /**
     * Outgoing data is put here. Since it is a SynchronousQueue, until {@link #outPump} is
     * interested in taking, putting an item blocks.
     */
    private final SynchronousQueue<Buffer> outQ = new SynchronousQueue<Buffer>();
    
    /**
     * This thread reads data byte-by-byte from the input stream, passing it on to
     * {@link PacketConverter#received(byte)} and this may result in a callback to
     * {@link #handle(Buffer)} when a full packet has been decoded. Thus a lot happens in this
     * thread's context.
     */
    private final Thread inPump = new Thread()
        {
            {
                setName("inPump");
                //setDaemon(true);
            }
            
            @Override
            public void run()
            {
                try {
                    while (!Thread.currentThread().isInterrupted())
                        packetConverter.received((byte) input.read());
                } catch (IOException e) {
                    // We are meant to shut up and draw to a close if interrupted
                    if (!Thread.currentThread().isInterrupted())
                        die(e);
                }
                log.debug("Stopping");
            }
        };
    
    /**
     * This thread waits for {@link #outQ} to offer some byte[] and sends the deliciousness over the
     * output stream for this session.
     */
    private final Thread outPump = new Thread()
        {
            {
                setName("outPump");
                //setDaemon(true);
            }
            
            @Override
            public void run()
            {
                try {
                    for (Buffer buf = null; !Thread.currentThread().isInterrupted(); buf =
                            outQ.poll(1, TimeUnit.SECONDS))
                        if (buf != null)
                            output.write(buf.getCompactData());
                } catch (InterruptedException ignore) {
                } catch (IOException e) {
                    // We are meant to shut up and draw to a close if interrupted
                    if (!Thread.currentThread().isInterrupted())
                        die(e);
                }
                log.debug("Stopping");
            }
        };
    
    /** Lock supporting correct encoding and queuing of packets */
    private final ReentrantLock writeLock = new ReentrantLock();
    
    /** For encoding and decoding SSH packets */
    final PacketConverter packetConverter;
    
    /** Psuedo-random number generator as retrieved from the factory manager */
    final Random prng;
    
    /** Whether this session has been authenticated */
    boolean authed = false;
    
    /** Client version identification string */
    String clientID = "SSH-2.0-" + VERSION;
    
    /** Server version identification string */
    String serverID;
    
    /**
     * 
     * @param factoryManager
     */
    public TransportProtocol(FactoryManager factoryManager)
    {
        assert factoryManager != null;
        fm = factoryManager;
        prng = factoryManager.getRandomFactory().create();
        packetConverter = new PacketConverter(this);
        negotiator = new Negotiator(this);
    }
    
    // Documented in interface
    public synchronized void addHostKeyVerifier(HostKeyVerifier hkv)
    {
        hostVerifiers.add(hkv);
    }
    
    // Documented in interface
    public boolean disconnect()
    {
        return disconnect(DisconnectReason.BY_APPLICATION);
    }
    
    // Documented in interface
    public boolean disconnect(DisconnectReason reason)
    {
        return disconnect(reason, "");
    }
    
    // Documented in interface
    public boolean disconnect(DisconnectReason reason, String msg)
    {
        if (msg == null)
            msg = "";
        log.debug("Sending SSH_MSG_DISCONNECT: reason=[{}], msg=[{}]", reason, msg);
        try {
            writePacket(new Buffer(Message.DISCONNECT) //
                                                      .putInt(reason.toInt()) //
                                                      .putString(msg) //
                                                      .putString("")); // lang tag
            return true;
        } catch (TransportException e) {
            log.error("unclean disconnect() - {}", e.toString());
            return false;
        } finally {
            stopPumping();
        }
    }
    
    // Documented in interface
    public String getClientVersion()
    {
        return clientID.substring(8);
    }
    
    // Documented in interface
    public FactoryManager getFactoryManager()
    {
        return fm;
    }
    
    // Documented in interface
    public long getLastSeqNum()
    {
        // (seqi - 1) because packetConverter always maintains the seq num applicable to the next packet
        return packetConverter.seqi - 1;
    }
    
    // Documented in interface
    public String getServerVersion()
    {
        return serverID == null ? serverID : serverID.substring(8);
    }
    
    // Documented in interface
    public synchronized Service getService()
    {
        return service;
    }
    
    // Documented in interface
    public byte[] getSessionID()
    {
        return negotiator.sessionID;
    }
    
    // Documented in interface
    public void init(Socket socket) throws TransportException
    {
        try {
            this.socket = socket;
            input = socket.getInputStream();
            output = socket.getOutputStream();
            
            log.info("Client identity string: {}", clientID);
            output.write((clientID + "\r\n").getBytes());
            
            // Read server's ID
            Buffer buf = new Buffer();
            while ((serverID = readIdentification(buf)) == null)
                buf.putByte((byte) input.read());
            log.info("Server identity string: {}", serverID);
            
        } catch (IOException e) {
            throw new TransportException(e);
        }
        
        // Delegate any incoming message to Negotiator
        sm.transition(State.KEX);
        
        // Start I/O threads
        inPump.start();
        outPump.start();
        
        // State negotiation from our end
        negotiator.sendKexInit();
        
        // Wait for completion
        sm.await(State.KEX_DONE);
    }
    
    // Documented in interface
    public boolean isRunning()
    {
        return sm.notIn(null, State.DEAD);
    }
    
    // Documented in interface
    public synchronized void reqService(Service service) throws TransportException
    {
        sm.transition(State.SERVICE_REQ);
        sendServiceRequest(service.getName());
        sm.await(State.SERVICE);
        setService(service);
    }
    
    // Documented in interface 
    public long sendUnimplemented(long seqNum) throws TransportException
    {
        return writePacket(new Buffer(Message.UNIMPLEMENTED).putInt(seqNum));
    }
    
    // Documented in interface
    public void setAuthenticated()
    {
        authed = true;
    }
    
    // Documented in interface
    public void setService(Service service)
    {
        if (sm.notIn(State.SERVICE))
            throw new IllegalStateException();
        log.info("Setting active service to {}", service.getName());
        this.service = service;
    }
    
    // Documented in interface
    public long writePacket(Buffer payload) throws TransportException
    {
        /*
         * Synchronize all write requests as needed by the encoding algorithm and also queue the
         * write request here to ensure packets are sent in the correct order.
         * 
         * NOTE: besides a thread invoking this method, writeLock may also be held by #handle in the
         * context of the inPump thread while key re-exchange is ongoing.
         */
        writeLock.lock();
        try {
            long seq = packetConverter.encode(payload);
            try {
                while (!outQ.offer(payload, 1L, TimeUnit.SECONDS))
                    if (!outPump.isAlive())
                        throw new TransportException("Output pumping thread is dead");
            } catch (InterruptedException e) {
                throw new TransportException(e);
            }
            return seq;
        } finally {
            writeLock.unlock();
        }
    }
    
    private synchronized void die(Exception ex)
    {
        log.error("Dying because - {}", ex.toString());
        SSHException causeOfDeath;
        if (ex instanceof SSHException)
            causeOfDeath = (SSHException) ex;
        else
            causeOfDeath = new SSHException(ex);
        
        // Takes care of notifying service
        if (service != null) {
            try {
                service.notifyError(causeOfDeath);
            } catch (Exception ignored) {
                log.debug("service spewed - {}", ignored.toString());
            }
            service = null;
        }
        
        if (Thread.currentThread() != outPump && causeOfDeath.getDisconnectReason() != DisconnectReason.UNKNOWN
                && cmd != Message.DISCONNECT)
            // Send SSH_MSG_DISCONNECT if - 
            // a) outPump can send (currentThread != outPump)
            // b) have the required info in the exception (disconnectReadon != unknown)
            // c) exception does not arise from receiving a SSH_MSG_DISCONNECT ourself (cmd != disconnect)
            disconnect(causeOfDeath.getDisconnectReason(), causeOfDeath.getMessage());
        else
            // simply stop both pumps
            stopPumping();
        
        // Throw the exception in any thread waiting for state change
        sm.interrupt(causeOfDeath);
    }
    
    /**
     * Got an SSH_MSG_UNIMPLEMENTED, so lets see where we're at and act accordingly.
     * 
     * @param seqNum
     * @throws TransportException
     */
    private synchronized void gotUnimplemented(long seqNum) throws SSHException
    {
        switch (sm.current())
        {
        case KEX:
            throw new TransportException("Received SSH_MSG_UNIMPLEMENTED while exchanging keys");
        case SERVICE_REQ:
            throw new TransportException("Server responded with SSH_MSG_UNIMPLEMENTED to service request for "
                    + service.getName());
        case SERVICE:
            if (service != null)
                // The service might throw an exception, but that's okay and encouraged
                service.notifyUnimplemented(seqNum);
        default:
            log.debug("Ignoring unimplemented message");
        }
    }
    
    /**
     * Reads the identification string from the SSH server. This is the very first string that is
     * sent upon connection by the server. It takes the form of, e.g. "SSH-2.0-OpenSSH_ver".
     * <p>
     * Several concerns are taken care of here, e.g. verifying protocol version, correct line
     * endings as specified in RFC and such.
     * 
     * @param buffer
     * @return
     * @throws IOException
     */
    private String readIdentification(Buffer buffer) throws IOException
    {
        String ident;
        
        byte[] data = new byte[256];
        for (;;) {
            int rpos = buffer.rpos();
            int pos = 0;
            boolean needLF = false;
            for (;;) {
                if (buffer.available() == 0) {
                    // Need more data, so undo reading and return null
                    buffer.rpos(rpos);
                    return null;
                }
                byte b = buffer.getByte();
                if (b == '\r') {
                    needLF = true;
                    continue;
                }
                if (b == '\n')
                    break;
                if (needLF)
                    throw new TransportException("Incorrect identification: bad line ending");
                if (pos >= data.length)
                    throw new TransportException("Incorrect identification: line too long");
                data[pos++] = b;
            }
            ident = new String(data, 0, pos);
            if (ident.startsWith("SSH-"))
                break;
            if (buffer.rpos() > 16 * 1024)
                throw new TransportException("Incorrect identification: too many header lines");
        }
        
        if (!ident.startsWith("SSH-2.0-") && !ident.startsWith("SSH-1.99-"))
            throw new TransportException(DisconnectReason.PROTOCOL_VERSION_NOT_SUPPORTED,
                                         "Server does not support SSHv2, identified as: " + ident);
        
        return ident;
    }
    
    /**
     * Sends a service request for the specified service
     * 
     * @param serviceName
     *            name of the service being requested
     * @throws TransportException
     *             if there is an error while sending the request
     */
    private void sendServiceRequest(String serviceName) throws TransportException
    {
        log.debug("Sending SSH_MSG_SERVICE_REQUEST for {}", serviceName);
        Buffer buffer = new Buffer(Message.SERVICE_REQUEST);
        buffer.putString(serviceName);
        writePacket(buffer);
    }
    
    private synchronized void stopPumping()
    {
        if (Thread.currentThread() != inPump)
            inPump.interrupt();
        if (Thread.currentThread() != outPump)
            outPump.interrupt();
        try {
            socket.close(); // Shock a thread into waking up if blocked on I/O
        } catch (IOException ignored) {
            log.debug("ignored - {}", ignored.toString());
        }
    }
    
    /**
     * This is where all incoming packets are handled. If they pertain to the transport layer, they
     * are handled here; otherwise they are delegated to the active service instance if any via
     * {@link Service#handle}.
     * <p>
     * Even among the transport layer specific packets, key exchange packets are delegated to
     * {@link Negotiator#handle}.
     * <p>
     * This method is called in the context of the {@link #inPump} thread via
     * {@link PacketConverter#munch} when a full packet has been decoded.
     * 
     * @param packet
     *            buffer containg the packet
     * @throws SSHException
     *             if an error occurs during handling
     */
    synchronized void handle(Buffer packet) throws SSHException
    {
        cmd = packet.getCommand();
        log.debug("Received packet {}", cmd);
        switch (cmd)
        {
        /*
         * Generic tranport layer packets
         */
        case DISCONNECT:
            DisconnectReason code = DisconnectReason.fromInt(packet.getInt());
            String message = packet.getString();
            log.info("Received SSH_MSG_DISCONNECT (reason={}, msg={})", code, message);
            throw new TransportException(code, message);
        case UNIMPLEMENTED:
            long seqNum = packet.getLong();
            log.info("Received SSH_MSG_UNIMPLEMENTED #{}", seqNum);
            gotUnimplemented(seqNum);
            break;
        case DEBUG:
            boolean display = packet.getBoolean();
            String msg = packet.getString();
            log.info("Received SSH_MSG_DEBUG (display={}) '{}'", display, msg);
            break;
        case IGNORE:
            log.info("Received SSH_MSG_IGNORE");
            break;
        default:
        {
            switch (sm.current())
            {
            case KEX:
                if (negotiator.handle(cmd, packet))
                    if (getService() == null) // Initial kex done
                        sm.transition(State.KEX_DONE);
                    else { // Re-exchange done
                        writeLock.unlock(); // This was acquired earlier, to prevent other packets through
                        sm.transition(State.SERVICE); // Back to SERVICE
                    }
                break;
            case KEX_DONE:
                // Deliberate fall-through
            case SERVICE:
                if (cmd == Message.KEXINIT) { // Re-exchange
                    sm.transition(State.KEX);
                    writeLock.lock(); // Prevent other packets being sent while re-ex is ongoing
                    negotiator.handle(cmd, packet);
                } else if (service != null)
                    service.handle(cmd, packet);
                break;
            case SERVICE_REQ:
                if (cmd != Message.SERVICE_ACCEPT)
                    throw new TransportException(DisconnectReason.PROTOCOL_ERROR, "Expected SSH_MSG_SERVICE_ACCEPT");
                sm.transition(State.SERVICE);
                break;
            default:
                assert false;
            }
        }
        }
    }
    
    /**
     * Tries to validate host key with all the host key verifiers known to this instance (
     * {@link #hostVerifiers})
     * 
     * @param key
     *            the host key to verify
     * @return {@code true} if host key could be verified, {@code false} if not
     */
    boolean verifyHost(PublicKey key)
    {
        while (!hostVerifiers.isEmpty()) {
            HostKeyVerifier hkv = hostVerifiers.remove();
            log.debug("Verifiying host key with [{}]", hkv);
            if (hkv.verify(socket.getInetAddress(), key))
                return true;
        }
        return false;
    }
    
}
