package org.apache.commons.net.ssh.connection;

public class OpenFailException extends ConnectionException
{
    
    public static final int ADMINISTRATIVELY_PROHIBITED = 1;
    public static final int CONNECT_FAILED = 2;
    public static final int UNKNOWN_CHANNEL_TYPE = 3;
    public static final int RESOURCE_SHORTAGE = 4;
    
    private final int failureReason;
    private final String channelType;
    
    public OpenFailException(String channelType, int failureReason, String message)
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