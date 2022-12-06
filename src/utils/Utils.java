package utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchProviderException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

public class Utils {
    public static X509CRL getCRL() {
		
		ByteArrayInputStream crlData = getDataFromUrl("http://test.ditec.sk/DTCCACrl/DTCCACrl.crl");

		if (crlData == null){
            return null;
		}
        
		CertificateFactory certFactory;
		try {
            certFactory = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
            return null;
		}
        
        
		X509CRL crl;
        
		try {
            crl = (X509CRL) certFactory.generateCRL(crlData);
		} catch (CRLException e) {
            return null;
		}


		return crl;
	}
    
    private static ByteArrayInputStream getDataFromUrl(String url) {
		
		URL urlHandler = null;
		try {
			urlHandler = new URL(url);
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		InputStream is = null;
		try {
			is = urlHandler.openStream();
			byte[] byteChunk = new byte[4096];
			int n;

			while ( (n = is.read(byteChunk)) > 0 ) {
				baos.write(byteChunk, 0, n);
			}
		}
		catch (IOException e) {
			System.err.printf ("Failed while reading bytes from %s: %s", urlHandler.toExternalForm(), e.getMessage());
			return null;
		}
		finally {
			if (is != null) {
				try {
					is.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}

		return new ByteArrayInputStream(baos.toByteArray());
	}

	public static TimeStampToken getTimestampToken(Document parsedXml) {
		
		TimeStampToken ts_token = null;

		Node timestamp = null;

		timestamp = parsedXml.getElementsByTagName("xades:EncapsulatedTimeStamp").item(0);

		if (timestamp == null){
			return null;
		}

		try {
			ts_token = new TimeStampToken(new CMSSignedData(Base64.decode(timestamp.getTextContent())));
		} catch (TSPException | IOException | CMSException e) {
			e.printStackTrace();
		}

		return ts_token;
	}
}
