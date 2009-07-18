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
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.commons.net.ssh.FactoryManager;
import org.apache.commons.net.ssh.HostKeyVerifier;
import org.apache.commons.net.ssh.SSHException;
import org.apache.commons.net.ssh.SSHRuntimeException;
import org.apache.commons.net.ssh.Service;
import org.apache.commons.net.ssh.random.Random;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Event;
import org.apache.commons.net.ssh.util.Constants.DisconnectReason;
import org.apache.commons.net.ssh.util.Constants.Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link Transport} implementation.
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
 */
public class TransportProtocol implements Transport
{
    
    private final Logger log = LoggerFactory.getLogger(getClass());
    
    private final FactoryManager fm;
    
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
    private final Kexer kexer;
    
    /** Message identifier for last packet received */
    private Message cmd;
    
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
    
    private final Lock lock = new ReentrantLock();
    
    private final Event<TransportException> kexOngoing = newEvent("transport / kex ongoing");
    private final Event<TransportException> kexDone = newEvent("transport / kex done");
    private final Event<TransportException> serviceRequested = newEvent("transport / service req");
    private final Event<TransportException> serviceAccepted = newEvent("transport / service accepted");
    private final Event<TransportException> closeEvent = newEvent("transport / close");
    
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
        kexer = new Kexer(this);
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
            close();
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
    
    public InetAddress getRemoteHost()
    {
        return socket.getInetAddress();
    }
    
    public int getRemotePort()
    {
        return socket.getPort();
    }
    
    // Documented in interface
    public String getServerVersion()
    {
        return serverID == null ? serverID : serverID.substring(8);
    }
    
    // Documented in interface
    public Service getService()
    {
        lock.lock();
        try {
            return service;
        } finally {
            lock.unlock();
        }
    }
    
    // Documented in interface
    public byte[] getSessionID()
    {
        return kexer.sessionID;
    }
    
    // Documented in interface
    public void init(Socket socket) throws TransportException
    {
        long t = System.currentTimeMillis();
        
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
        
        lock.lock();
        try {
            
            kexOngoing.set();
            
            // Start negotiation from our end
            kexer.init();
            
            // Start dealing with input
            inPump.start();
            
            // Wait for completion
            kexDone.await();
            
        } finally {
            lock.unlock();
        }
        
        log.info("Connection to {} initialized in {} seconds", socket.getRemoteSocketAddress(),
                 ((System.currentTimeMillis() - t) / 1000.0));
    }
    
    // Documented in interface
    public boolean isRunning()
    {
        return !closeEvent.isSet();
    }
    
    // Documented in interface
    public synchronized void reqService(Service service) throws TransportException
    {
        lock.lock();
        try {
            serviceRequested.set();
            sendServiceRequest(service.getName());
            serviceAccepted.await();
            setService(service);
        } finally {
            lock.unlock();
        }
    }
    
    // Documented in interface 
    public long sendUnimplemented() throws TransportException
    {
        // (seqi - 1) because packetConverter always maintains the seq num applicable to the next packet
        long seq = packetConverter.seqi - 1;
        log.info("Sending SSH_MSG_UNIMPLEMENTED for packet #{}", seq);
        return writePacket(new Buffer(Message.UNIMPLEMENTED).putInt(seq));
    }
    
    // Documented in interface
    public void setAuthenticated()
    {
        synchronized (packetConverter) {
            authed = true;
        }
    }
    
    // Documented in interface
    public synchronized void setService(Service service)
    {
        lock.lock();
        try {
            if (!serviceAccepted.isSet())
                throw new SSHRuntimeException("Contract violation");
            log.info("Setting active service to {}", service.getName());
            this.service = service;
        } finally {
            lock.unlock();
        }
    }
    
    // Documented in interface
    public long writePacket(Buffer payload) throws TransportException
    {
        /*
         * Ensure packets sent in correct order
         */
        // While exchanging or re-exchanging...
        if (kexOngoing.isSet()) {
            int cmd = payload.getByte();
            // Only transport layer packets (1 to 49) allowed except SERVICE_REQUEST (5)
            if (cmd == 5 || !(cmd >= 1 && cmd <= 49))
                kexDone.await();
            payload.rpos(payload.rpos() - 1);
        }
        synchronized (packetConverter) {
            long seq = packetConverter.encode(payload);
            try {
                output.write(payload.getCompactData());
            } catch (IOException e) {
                throw new TransportException(e);
            }
            return seq;
        }
    }
    
    private void close()
    {
        inPump.interrupt();
        if (socket != null) {
            try { // Shock it into waking up if blocked on I/O
                socket.close();
            } catch (IOException ignored) {
                log.debug("Ignored - {}", ignored.toString());
            }
            socket = null;
        }
        closeEvent.set();
    }
    
    @SuppressWarnings("unchecked")
    private void die(IOException ex)
    {
        
        log.error("Dying because - {}", ex.toString());
        
        SSHException causeOfDeath = SSHException.chainer.chain(ex);
        
        lock.lock();
        try {
            
            // Takes care of notifying service
            if (service != null) {
                log.debug("Notifying {}", service);
                try {
                    service.notifyError(causeOfDeath);
                } catch (Exception ignored) {
                    log.debug("Service spewed - {}", ignored.toString());
                }
                service = null;
            }
            
            // Throw the exception in any thread waiting for state change
            Event.Util.<TransportException> notifyError(causeOfDeath, kexOngoing, kexDone, closeEvent,
                                                        serviceRequested, serviceAccepted);
            
            if (causeOfDeath.getDisconnectReason() != DisconnectReason.UNKNOWN && cmd != Message.DISCONNECT)
                /*
                 * Send SSH_MSG_DISCONNECT if we have the required info in the exception and the
                 * exception does not arise from receiving a SSH_MSG_DISCONNECT ourself
                 */
                disconnect(causeOfDeath.getDisconnectReason(), causeOfDeath.getMessage());
            else
                // stop inPump without sending disconnect message
                close();
            
        } finally {
            lock.unlock();
        }
    }
    
    /**
     * Got an SSH_MSG_UNIMPLEMENTED, so lets see where we're at and act accordingly.
     * 
     * @param seqNum
     * @throws TransportException
     */
    private void gotUnimplemented(long seqNum) throws SSHException
    {
        lock.lock();
        try {
            if (kexOngoing.isSet())
                throw new TransportException("Received SSH_MSG_UNIMPLEMENTED while exchanging keys");
            else if (serviceRequested.isSet())
                throw new TransportException("Server responded with SSH_MSG_UNIMPLEMENTED to service request for "
                        + service.getName());
            else if (serviceAccepted.isSet()) {
                if (service != null)
                    // The service might throw an exception, but that's okay and encouraged
                    service.notifyUnimplemented(seqNum);
            } else
                log.warn("Ignoring unimplemented message");
        } finally {
            lock.unlock();
        }
    }
    
    private Event<TransportException> newEvent(String name)
    {
        return new Event<TransportException>(name, TransportException.chainer, lock);
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
            int savedPos = buffer.rpos();
            int pos = 0;
            boolean needLF = false;
            for (;;) {
                if (buffer.available() == 0) {
                    // Need more data, so undo reading and return null
                    buffer.rpos(savedPos);
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
    
    /**
     * This is where all incoming packets are handled. If they pertain to the transport layer, they
     * are handled here; otherwise they are delegated to the active service instance if any via
     * {@link Service#handle}.
     * <p
     * Even among the transport layer specific packets, key exchange packets are delegated to
     * {@link Kexer#handle}.
     * <p>
     * This method is called in the context of the {@link #inPump} thread via
     * {@link PacketConverter#munch} when a full packet has been decoded.
     * 
     * @param packet
     *            buffer containg the packet
     * @throws SSHException
     *             if an error occurs during handling
     */
    void handle(Buffer packet) throws SSHException
    {
        cmd = packet.getCommand();
        log.debug("Received packet {}", cmd);
        switch (cmd)
        {
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
                lock.lock();
                try {
                    if (kexOngoing.isSet()) {
                        if (kexer.handle(cmd, packet)) {
                            kexDone.set();
                            kexOngoing.clear();
                        }
                    } else if (serviceRequested.isSet()) {
                        if (cmd != Message.SERVICE_ACCEPT)
                            throw new TransportException(DisconnectReason.PROTOCOL_ERROR,
                                                         "Expected SSH_MSG_SERVICE_ACCEPT");
                        serviceAccepted.set();
                        serviceRequested.clear();
                    } else if (serviceAccepted.isSet() && cmd.toInt() > 49) // Not a transport layer packet
                        if (service != null)
                            service.handle(cmd, packet);
                        else if (cmd == Message.KEXINIT) { // Start re-exchange
                            kexOngoing.set();
                            kexer.handle(cmd, packet);
                        } else
                            sendUnimplemented();
                    else
                        sendUnimplemented();
                } finally {
                    lock.unlock();
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
    synchronized boolean verifyHost(PublicKey key)
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
