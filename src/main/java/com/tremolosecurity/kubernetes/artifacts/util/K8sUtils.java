//    Copyright 2018 Tremolo Security, Inc.
// 
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
// 
//        http://www.apache.org/licenses/LICENSE-2.0
// 
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

package com.tremolosecurity.kubernetes.artifacts.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import com.tremolosecurity.kubernetes.artifacts.obj.HttpCon;

import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.message.BasicHeader;
import org.apache.http.util.EntityUtils;

/**
 * K8sUtils
 */
public class K8sUtils {
    String token;
    private KeyStore ks;
    private String ksPassword;
    private KeyManagerFactory kmf;
	private Registry<ConnectionSocketFactory> httpClientRegistry;
    private RequestConfig globalHttpClientConfig;
    String url;


    public K8sUtils(String pathToToken,String pathToCA,String pathToMoreCerts,String apiServerURL) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, KeyManagementException {
        //get the token for talking to k8s
        this.token = new String(Files.readAllBytes(Paths.get(pathToToken)), StandardCharsets.UTF_8);

        this.ksPassword = UUID.randomUUID().toString();
        this.ks = KeyStore.getInstance("PKCS12");
        this.ks.load(null, this.ksPassword.toCharArray());


        String caCert = new String(Files.readAllBytes(Paths.get(pathToCA)), StandardCharsets.UTF_8);

        CertUtils.importCertificate(ks, ksPassword, "k8s-master", caCert);

        File moreCerts = new File(pathToMoreCerts);
        if (moreCerts.exists() && moreCerts.isDirectory()) {
            for (File certFile : moreCerts.listFiles()) {
                System.out.println("Processing - '" + certFile.getAbsolutePath() + "'");
                if (certFile.isDirectory()) {
                    System.out.println("not a pem, sipping");
                    continue;
                }
                String certPem = new String(Files.readAllBytes(Paths.get(certFile.getAbsolutePath())), StandardCharsets.UTF_8);
                String alias = certFile.getName().substring(0,certFile.getName().indexOf('.'));
                CertUtils.importCertificate(ks, ksPassword, alias, certPem);
            }
        }

        KeyStore cacerts = KeyStore.getInstance(KeyStore.getDefaultType());
        String cacertsPath = System.getProperty("javax.net.ssl.trustStore");
        if (cacertsPath == null) {
            cacertsPath = System.getProperty("java.home") + "/lib/security/cacerts";
        }
        
        cacerts.load(new FileInputStream(cacertsPath), null);
        
        Enumeration<String> enumer = cacerts.aliases();
        while (enumer.hasMoreElements()) {
            String alias = enumer.nextElement();
            java.security.cert.Certificate cert = cacerts.getCertificate(alias);
            ks.setCertificateEntry(alias, cert);
        }
        
        this.kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(this.ks, this.ksPassword.toCharArray());

        SSLContext sslctx = SSLContexts.custom().loadTrustMaterial(this.ks).loadKeyMaterial(this.ks,this.ksPassword.toCharArray()).build();
		SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslctx,SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
		
		PlainConnectionSocketFactory sf = PlainConnectionSocketFactory.getSocketFactory();
		this.httpClientRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
		        .register("http", sf)
		        .register("https", sslsf)
		        .build();
		
		this.globalHttpClientConfig = RequestConfig.custom().setCookieSpec(CookieSpecs.IGNORE_COOKIES).setRedirectsEnabled(false).setAuthenticationEnabled(false).build();

        this.url = apiServerURL;

    }

    public HttpCon createClient() throws Exception {
		ArrayList<Header> defheaders = new ArrayList<Header>();
		defheaders.add(new BasicHeader("X-Csrf-Token", "1"));

		BasicHttpClientConnectionManager bhcm = new BasicHttpClientConnectionManager(
				this.httpClientRegistry);

		RequestConfig rc = RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).setRedirectsEnabled(false)
				.build();

		CloseableHttpClient http = HttpClients.custom()
				                  .setConnectionManager(bhcm)
				                  .setDefaultHeaders(defheaders)
				                  .setDefaultRequestConfig(rc)
				                  .build();

		HttpCon con = new HttpCon();
		con.setBcm(bhcm);
		con.setHttp(http);

		return con;

	}

    public Map callWS(String uri) throws Exception {
        
        StringBuffer b = new StringBuffer();
		
		b.append(this.url).append(uri);
		HttpGet get = new HttpGet(b.toString());
		b.setLength(0);
		b.append("Bearer ").append(token);
        get.addHeader(new BasicHeader("Authorization","Bearer " + token));
        
        HttpCon con = this.createClient();
        try {
		    HttpResponse resp = con.getHttp().execute(get);
		    String json = EntityUtils.toString(resp.getEntity());
            Map ret = new HashMap();
            ret.put("code",resp.getStatusLine().getStatusCode());
            ret.put("data",json);
            return ret;
        } finally {
            if (con != null) {
				con.getBcm().shutdown();
			}
        }
    }

    public Map deleteWS(String uri) throws Exception {
        
        StringBuffer b = new StringBuffer();
		
		b.append(this.url).append(uri);
		HttpDelete delete = new HttpDelete(b.toString());
		b.setLength(0);
		b.append("Bearer ").append(token);
        delete.addHeader(new BasicHeader("Authorization","Bearer " + token));
        
        HttpCon con = this.createClient();
        try {
		    HttpResponse resp = con.getHttp().execute(delete);
		    String json = EntityUtils.toString(resp.getEntity());
            Map ret = new HashMap();
            ret.put("code",resp.getStatusLine().getStatusCode());
            ret.put("data",json);
            return ret;
        } finally {
            if (con != null) {
				con.getBcm().shutdown();
			}
        }
    }
    
    public Map postWS(String uri,String json) throws Exception {
        StringBuffer b = new StringBuffer();
		
		b.append(this.url).append(uri);
		HttpPost post = new HttpPost(b.toString());
		b.setLength(0);
		b.append("Bearer ").append(token);
        post.addHeader(new BasicHeader("Authorization","Bearer " + token));
        
        StringEntity str = new StringEntity(json,ContentType.APPLICATION_JSON);
		post.setEntity(str);

        HttpCon con = this.createClient();
        try {
		    HttpResponse resp = con.getHttp().execute(post);
		    String jsonResponse = EntityUtils.toString(resp.getEntity());
            Map ret = new HashMap();
            ret.put("code",resp.getStatusLine().getStatusCode());
            ret.put("data",jsonResponse);
            return ret;
        } finally {
            if (con != null) {
				con.getBcm().shutdown();
			}
        }
    }

    public Map putWS(String uri,String json) throws Exception {
        StringBuffer b = new StringBuffer();
		
		b.append(this.url).append(uri);
		HttpPut post = new HttpPut(b.toString());
		b.setLength(0);
		b.append("Bearer ").append(token);
        post.addHeader(new BasicHeader("Authorization","Bearer " + token));
        
        StringEntity str = new StringEntity(json,ContentType.APPLICATION_JSON);
		post.setEntity(str);

        HttpCon con = this.createClient();
        try {
		    HttpResponse resp = con.getHttp().execute(post);
		    String jsonResponse = EntityUtils.toString(resp.getEntity());
            Map ret = new HashMap();
            ret.put("code",resp.getStatusLine().getStatusCode());
            ret.put("data",jsonResponse);
            return ret;
        } finally {
            if (con != null) {
				con.getBcm().shutdown();
			}
        }
    }


    public X509Certificate getCertificate(String name) throws KeyStoreException {
        return (X509Certificate) this.ks.getCertificate(name);
    }

    public String encodeMap(Map data) throws UnsupportedEncodingException {
        String vals = "";
        for (Object k : data.keySet()) {
            vals += k + "=" + data.get(k) + "\n";
        }
        vals = vals.substring(0,vals.length()-1);
        return Base64.getEncoder().encodeToString(vals.getBytes("UTF-8"));
    }
    
}