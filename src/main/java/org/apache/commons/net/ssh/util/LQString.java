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
package org.apache.commons.net.ssh.util;

// TODO: the language tags are always empty? + we don't negotiate langs + maybe simply use a String and scrap this language qualified business? 

/**
 * This class represents a "language-qualified" user-visible string in the SSH protocol; which are
 * qualified with an RFC 3066 language tag.
 * 
 * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
 */
public class LQString
{
    
    private final String text;
    private final String langTag;
    
    /**
     * Construct with the 2 strings which constitute a language qualified string
     * 
     * @param text
     *            the content that is qualified
     * @param langTag
     *            the language tag
     */
    public LQString(String text, String langTag)
    {
        this.text = text;
        this.langTag = langTag;
    }
    
    /**
     * Returns the language tag.
     * 
     * @return langauge tag
     */
    public String getLanguage()
    {
        return langTag;
    }
    
    /**
     * The content for this string.
     * 
     * @return content
     */
    public String getText()
    {
        return text;
    }
    
    @Override
    public String toString()
    {
        return text;
    }
    
}
