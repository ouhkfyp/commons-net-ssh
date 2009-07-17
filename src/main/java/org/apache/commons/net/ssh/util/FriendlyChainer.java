package org.apache.commons.net.ssh.util;

/**
 * A FriendlyChainer's motto is to prevent meaningless chaining, i.e.
 * 
 * <pre>
 * FriendlyChainer&lt;SomeException&gt; chainer = new FriendlyChainer&lt;SomeException&gt;()
 *     {
 *         public SomeException chain(Throwable t)
 *         {
 *             if (t instanceof SomeException)
 *                 return (SomeException) t;
 *             else
 *                 return new SomeExcepion(t);
 *         }
 *     };
 * </pre>
 * 
 * @param <Z>
 *            Throwable type
 */
public interface FriendlyChainer<Z extends Throwable>
{
    
    Z chain(Throwable t);
    
}