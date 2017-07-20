/*
 * Licensed to the University Corporation for Advanced Internet Development, 
 * Inc. (UCAID) under one or more contributor license agreements.  See the 
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache 
 * License, Version 2.0 (the "License"); you may not use this file except in 
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.opensaml.saml2.metadata.provider;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Timer;
import java.util.zip.GZIPInputStream;
import java.util.zip.InflaterInputStream;

import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.config.SocketConfig;
import org.apache.http.impl.client.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A metadata provider that pulls metadata using an HTTP GET. Metadata is cached until one of these criteria is met:
 * <ul>
 * <li>The smallest cacheDuration within the metadata is exceeded</li>
 * <li>The earliest validUntil time within the metadata is exceeded</li>
 * <li>The maximum cache duration is exceeded</li>
 * </ul>
 * 
 * Metadata is filtered prior to determining the cache expiration data. This allows a filter to remove XMLObjects that
 * may effect the cache duration but for which the user of this provider does not care about.
 * 
 * It is the responsibility of the caller to re-initialize, via {@link #initialize()}, if any properties of this
 * provider are changed.
 */
public class HTTPMetadataProvider extends AbstractReloadingMetadataProvider {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(HTTPMetadataProvider.class);

    /** HTTP Client used to pull the metadata. */
    private CloseableHttpClient closeableHttpClient;

    /** URL to the Metadata. */
    private URI metadataURI;

    /** The ETag provided when the currently cached metadata was fetched. */
    private String cachedMetadataETag;

    /** The Last-Modified information provided when the currently cached metadata was fetched. */
    private String cachedMetadataLastModified;

    /** URL scope that requires authentication. */
    private AuthScope authScope;

    private int requestTimeout;

    private HttpClientContext httpClientContext;


    /**
     * Constructor.
     * 
     * @param metadataURL the URL to fetch the metadata
     * @param requestTimeout the time, in milliseconds, to wait for the metadata server to respond
     * 
     * @throws MetadataProviderException thrown if the URL is not a valid URL or the metadata can not be retrieved from
     *             the URL
     */
    @Deprecated
    public HTTPMetadataProvider(String metadataURL, int requestTimeout) throws MetadataProviderException {
        super();
        try {
            metadataURI = new URI(metadataURL);
        } catch (URISyntaxException e) {
            throw new MetadataProviderException("Illegal URL syntax", e);
        }
        this.requestTimeout = requestTimeout;
        httpClientContext = HttpClientContext.create();

        closeableHttpClient = HttpClients.custom()
                .setDefaultSocketConfig(SocketConfig.custom().setSoTimeout(requestTimeout).build())
                .build();

        authScope = new AuthScope(metadataURI.getHost(), metadataURI.getPort());
    }

    /**
     * Constructor.
     * 
     * @param client HTTP client used to pull in remote metadata
     * @param backgroundTaskTimer timer used to schedule background metadata refresh tasks
     * @param metadataURL URL to the remove remote metadata
     * 
     * @throws MetadataProviderException thrown if the HTTP client is null or the metadata URL provided is invalid
     */
    public HTTPMetadataProvider(Timer backgroundTaskTimer, CloseableHttpClient client, String metadataURL)
            throws MetadataProviderException {
        super(backgroundTaskTimer);

        if (client == null) {
            throw new MetadataProviderException("HTTP client may not be null");
        }

        try {
            metadataURI = new URI(metadataURL);
        } catch (URISyntaxException e) {
            throw new MetadataProviderException("Illegal URL syntax", e);
        }
        httpClientContext = HttpClientContext.create();
        this.closeableHttpClient = client;
        authScope = new AuthScope(metadataURI.getHost(), metadataURI.getPort());
    }

    /**
     * Gets the URL to fetch the metadata.
     * 
     * @return the URL to fetch the metadata
     */
    public String getMetadataURI() {
        return metadataURI.toASCIIString();
    }

    /**
     * Sets the username and password used to access the metadata URL. To disable BASIC authentication set the username
     * and password to null;
     * 
     * @param username the username
     * @param password the password
     */
    public void setBasicCredentials(String username, String password) {
        CredentialsProvider credsProvider = new BasicCredentialsProvider();
        credsProvider.setCredentials(AuthScope.ANY, new UsernamePasswordCredentials(username, password));

        // Add AuthCache to the execution context
        this.httpClientContext.setCredentialsProvider(credsProvider);
    }

    /**
     * Gets the length of time in milliseconds to wait for the server to respond.
     * 
     * @return length of time in milliseconds to wait for the server to respond
     */
    public int getRequestTimeout() {
        return requestTimeout;
    }

    /**
     * Gets the maximum amount of time, in seconds, metadata will be cached for.
     * 
     * @return maximum amount of time, in seconds, metadata will be cached for
     * 
     * @deprecated use {@link #getMaxRefreshDelay()} instead
     */
    public int getMaxCacheDuration() {
        return (int) getMaxRefreshDelay();
    }

    /**
     * Sets the maximum amount of time, in seconds, metadata will be cached for.
     * 
     * @param newDuration maximum amount of time, in seconds, metadata will be cached for
     * 
     * @deprecated use {@link #setMaxRefreshDelay(long)} instead
     */
    public void setMaxCacheDuration(int newDuration) {
        setMaxRefreshDelay(newDuration * 1000);
    }

    /**
     * Gets whether cached metadata should be discarded if it expires and can not be refreshed.
     * 
     * @return whether cached metadata should be discarded if it expires and can not be refreshed.
     * 
     * @deprecated use {@link #requireValidMetadata()} instead
     */
    public boolean maintainExpiredMetadata() {
        return !requireValidMetadata();
    }

    /**
     * Sets whether cached metadata should be discarded if it expires and can not be refreshed.
     * 
     * @param maintain whether cached metadata should be discarded if it expires and can not be refreshed.
     * 
     * @deprecated use {@link #setRequireValidMetadata(boolean)} instead
     */
    public void setMaintainExpiredMetadata(boolean maintain) {
        setRequireValidMetadata(!maintain);
    }

    /** {@inheritDoc} */
    public synchronized void destroy() {
        if (closeableHttpClient!=null)
            try {
                closeableHttpClient.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        closeableHttpClient = null;
        metadataURI = null;
        cachedMetadataETag = null;
        cachedMetadataLastModified = null;
        authScope = null;
        
        super.destroy();
    }
    
    /** {@inheritDoc} */
    protected String getMetadataIdentifier() {
        return metadataURI.toString();
    }

    /**
     * Gets the metadata document from the remote server.
     * 
     * @return the metadata from remote server, or null if the metadata document has not changed since the last
     *         retrieval
     * 
     * @throws MetadataProviderException thrown if there is a problem retrieving the metadata from the remote server
     */
    protected byte[] fetchMetadata() throws MetadataProviderException {
        HttpGet httpGet = buildGetMethod();

        try {
            log.debug("Attempting to fetch metadata document from '{}'", metadataURI);
            final CloseableHttpResponse response = closeableHttpClient.execute(httpGet, httpClientContext);
            int httpStatus = response.getStatusLine().getStatusCode();

            if (httpStatus == HttpStatus.SC_NOT_MODIFIED) {
                log.debug("Metadata document from '{}' has not changed since last retrieval", getMetadataURI());
                return null;
            }

            if (response.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
                String errMsg = "Non-ok status code " + response.getStatusLine().getStatusCode()
                        + " returned from remote metadata source " + metadataURI;
                log.error(errMsg);
                throw new MetadataProviderException(errMsg);
            }

            processConditionalRetrievalHeaders(response);

            byte[] rawMetadata = getMetadataBytesFromResponse(response);
            log.debug("Successfully fetched {}bytes of metadata from {}", rawMetadata.length, getMetadataURI());

            return rawMetadata;
        } catch (IOException e) {
            String errMsg = "Error retrieving metadata from " + metadataURI;
            log.error(errMsg, e);
            throw new MetadataProviderException(errMsg, e);
        }finally{
            httpGet.releaseConnection();
        }
    }

    /**
     * Builds the HTTP GET method used to fetch the metadata. The returned method advertises support for GZIP and
     * deflate compression, enables conditional GETs if the cached metadata came with either an ETag or Last-Modified
     * information, and sets up basic authentication if such is configured.
     * 
     * @return the constructed GET method
     */
    protected HttpGet buildGetMethod() {
        HttpGet getMethod = new HttpGet(getMetadataURI());
        getMethod.addHeader("Connection", "close");

        getMethod.addHeader("Accept-Encoding", "gzip,deflate");
        if (cachedMetadataETag != null) {
            getMethod.addHeader("If-None-Match", cachedMetadataETag);
        }
        if (cachedMetadataLastModified != null) {
            getMethod.addHeader("If-Modified-Since", cachedMetadataLastModified);
        }


        return getMethod;
    }

    /**
     * Records the ETag and Last-Modified headers, from the response, if they are present.
     * 
     * @param response GetMethod containing a valid HTTP response
     */
    protected void processConditionalRetrievalHeaders(CloseableHttpResponse response) {
        Header[] httpHeader = response.getHeaders("ETag");
        Header header = httpHeader[0];
        if (header != null) {
            cachedMetadataETag = header.getValue();
        }

        httpHeader = response.getHeaders("Last-Modified");
        Header headerLM = httpHeader[0];
        if (headerLM != null) {
            cachedMetadataLastModified = headerLM.getValue();
        }
    }

    /**
     * Extracts the raw metadata bytes from the response taking in to account possible deflate and GZip compression.
     * 
     * @param getMethod GetMethod containing a valid HTTP response
     * 
     * @return the raw metadata bytes
     * 
     * @throws MetadataProviderException thrown if there is a problem getting the raw metadata bytes from the response
     */
    protected byte[] getMetadataBytesFromResponse(CloseableHttpResponse response) throws MetadataProviderException {
        log.debug("Attempting to extract metadata from response to request for metadata from '{}'", getMetadataURI());
        try {
            InputStream ins = response.getEntity().getContent();

            Header[] httpHeaders = response.getHeaders("Content-Encoding");
            Header header = httpHeaders[0];
            if (header != null) {
                String contentEncoding = header.getValue();
                if ("deflate".equalsIgnoreCase(contentEncoding)) {
                    log.debug("Metadata document from '{}' was deflate compressed, decompressing it", metadataURI);
                    ins = new InflaterInputStream(ins);
                }

                if ("gzip".equalsIgnoreCase(contentEncoding)) {
                    log.debug("Metadata document from '{}' was GZip compressed, decompressing it", metadataURI);
                    ins = new GZIPInputStream(ins);
                }
            }

            return inputstreamToByteArray(ins);
        } catch (IOException e) {
            log.error("Unable to read response", e);
            throw new MetadataProviderException("Unable to read response", e);
        }
    }
}