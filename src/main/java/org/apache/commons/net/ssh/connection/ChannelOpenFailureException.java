package org.apache.commons.net.ssh.connection;

public class ChannelOpenFailureException extends ConnectionException
{
    
    public static final int SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 0;
    public static final int SSH_OPEN_CONNECT_FAILED = 2;
    public static final int SSH_OPEN_UNKNOWN_CHANNEL_TYPE = 3;
    public static final int SSH_OPEN_RESOURCE_SHORTAGE = 4;
    
    private final int failureReason;
    private final String channelType;
    
    public ChannelOpenFailureException(String channelType, int failureReason, String message)
    {
        super(message);
        this.channelType = channelType;
        this.failureReason = failureReason;
    }
    
    public String getChannelType()
    {
        return channelType;
    }
    
    public int getFailureReason()
    {
        return failureReason;
    }
    
}