package com.mps.deepviolettools.job;


import java.net.URL;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mps.deepviolet.api.DVException;
import com.mps.deepviolet.api.DVFactory;
import com.mps.deepviolet.api.IDVCipherSuite;
import com.mps.deepviolet.api.IDVEng;
import com.mps.deepviolet.api.IDVHost;
import com.mps.deepviolet.api.IDVSession;
import com.mps.deepviolet.api.IDVSession.SESSION_PROPERTIES;
import com.mps.deepviolet.api.IDVX509Certificate;
import com.mps.deepviolet.api.IDVX509Certificate.ValidState;

import com.mps.deepviolettools.job.UIBackgroundTask;

/**
 * Coordinates the order and execution of scan tasks
 * 
 * @author Milton Smith
 */
public class DeepScanTask extends UIBackgroundTask {

	private static final Logger logger = LoggerFactory
			.getLogger("com.mps.deepviolettools.job.UIBackgroundTask");

	private final String EOL = System.getProperty("line.separator");
	protected volatile StringBuffer con = new StringBuffer();

	private IDVEng eng;
	private IDVSession session;
	private URL url;
	private String filename;

	public volatile boolean bHeader = true;
	public volatile boolean bHostSection = true;
	public volatile boolean bHTTPResponseSection = true;
	public volatile boolean bConnectionSection = true;
	public volatile boolean bCiperSuitSection = true;
	public volatile boolean bServerCertficateSection = true;
	public volatile boolean bCertChainSection = true;
	public volatile boolean bServerAnalysisSection = true;
	public volatile boolean bWriteCertificate = false;
	public volatile boolean bReadCertificate = false;

	private IDVHost[] dvHosts;
	IDVX509Certificate dvCert;

	/**
	 * CTOR
	 * 
	 * @param url
	 *            Target URL of TLS scan
	 * @throws DVException
	 *             thrown on host initialization problems
	 */
	public DeepScanTask(URL url) throws DVException {

		this.url = url;
		this.session = DVFactory.initializeSession(url);
		eng = DVFactory.getDVEng(session);
		dvCert = eng.getCertificate();
		dvHosts = session.getHostInterfaces();

	}

	/**
	 * Return the current URL
	 * 
	 * @return Host URL
	 */
	public URL getURL() {

		return url;

	}

	/**
	 * Retrieve the status message for each task to communicate on the UI to
	 * users
	 * 
	 * @return String Status message.
	 */
	public String getLargeStatusMessage() {

		return con.toString();

	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolettools.api.IDVPrint#printReportHeader()
	 */
	public void printReportHeader() {
		
		Date d = new Date();
		println("");
		println("***********************************************************************");
		println("***********************************************************************");
		println("*  NOTICE: THIS SOFTWARE IS PROVIDED FOR RESEARCH PURPOSES AND NOT     ");
		println("*          RECOMMENDED FOR USE ON PRODUCTION SYSTEMS.  SEE PROJECT     ");
		println("*          INFORMATION ON GITHUB FOR FURTHER DETAILS,                  ");
		println("*          https://github.com/spoofzu/DeepViolet                       ");
		println("***********************************************************************");
		println("***********************************************************************");
		println("");
		println("[Report run information]");
		println("DeepViolet "+ eng.getDeepVioletStringVersion());
		println("Report generated on "+d.toString());
		if( session.getURL() != null ) {
			println("Target url "+session.getURL().toString());	
		}
		//TODO: PRINT THE LOGBACK FILE LOCATION, LOCATION OF CACERTS, AND VERSION OF JAVA
		
	}
	
	/**
	 * End of Line(EOL) for active operating system
	 * @return EOL sequence.
	 */
	public final String getEOL(){
		return EOL;
	}
	
	/**
	 * Output a single line of text to buffer with line feed.
	 * @param text Print line of text to console buffer.
	 */
	public final void println( String text ) {
		
		con.append(text);
		con.append(EOL);
		
		logger.info(text);
				
}

//	/* (non-Javadoc)
//	 * @see com.mps.deepviolettools.api.IDVPrint#printCertificate(java.lang.String)
//	 */
//	public void printCertificate( String file ) {
//		
//		  try {
//			  File f = new File(file);
//		      FileInputStream fs = new FileInputStream(f);
//		      
//		      CertificateFactory cf = CertificateFactory.getInstance("X.509");
//		      Collection c = cf.generateCertificates(fs);
//		      Iterator i = c.iterator();
//		      
//		      while (i.hasNext()) {
//		    	 X509Certificate lcert = (X509Certificate)i.next();
//		    	 DVX509Certificate ldvCert = new DVX509Certificate(eng,lcert);
//		    	 printTrustState( ldvCert );
//		    	 printX509Certificate(ldvCert);
//		      }
//		      
//		  } catch( DVException e ) {
//				println("Read certificate failed. reason="+e.getMessage()+" file="+file );
//				println(""); 
//		  } catch( FileNotFoundException e ) {
//				println("Read certificate failed. reason=file not found.  file="+file );
//				println("");
//		  } catch( CertificateException e ) {
//				println("Read certificate failed.  reason="+e.getMessage()+" file="+file );
//				println("");
//				logger.error("Read certificate failed.  reason="+e.getMessage()+" file="+file );
//		  }
//		
//}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolettools.api.IDVPrint#printHostInformation()
	 */
	public void printHostInformation() {
		
		println("");
		println("[Host information]");
		
        try {
        	
    		IDVHost[] hosts = this.dvHosts;
    		
    		for( IDVHost host : hosts ) {
    			
            	StringBuffer buff = new StringBuffer();
            	buff.append( "host="+host.getHostName()+" ["+host.getHostIPAddress()+"], ");
            	buff.append("canonical="+host.getHostCannonicalName());
            	println( buff.toString());
    			
    		}
	        
		} catch (Exception e) {
        	println("Can't fetch host. err="+e.getMessage() );
			println("");
        	logger.error("Can't fetch host. err="+e.getMessage(),e);
		}
	
}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolettools.api.IDVPrint#printHostHttpResponseHeaders()
	 */
	public void printHostHttpResponseHeaders( ) {
		
		println("");
		println("[HTTP(S) response headers]");
		
		Map<String, List<String>> headers = session.getHttpResponseHeaders();
		
		for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
			
			String key = (String)entry.getKey();
			
			List<String> vlist = entry.getValue();
			
			for ( String value: vlist ) {
				
				key = (key == null ) ? "<null>" : key;
				key = (key.length() > 5000) ? key.substring(0,5000)+"[truncated by DeepViolet sz="+key.length()+"]" : key;

				value = (value == null ) ? "<null>" : value;
				value = (value.length() > 5000) ? value.substring(0,5000)+"[truncated by DeepViolet sz="+key.length()+"]" : value;	
				
		      	println( key+" : "+value );
				
			}
			
		}	
			
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolettools.api.IDVPrint#printConnectionCharacteristics()
	 */
	public void printConnectionCharacteristics() {
		
		println( "" );
		println( "[Connection characteristics]" );
		
//		IDVHost[] dvhosts = this.dvHosts;
//		
//		if( dvhosts.length < 1 ) {
//        	println("No host data returned. err=dvhost is null");
//        	return;
//		}
		
		IDVSession.SESSION_PROPERTIES[] connection_properties = session.getPropertyNames();
		for( IDVSession.SESSION_PROPERTIES key : connection_properties ) {
			
        	println( key+"="+session.getPropertyValue(key) );
        	
		}
			
}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolettools.api.IDVPrint#printSupportedCipherSuites()
	 */
	public void printSupportedCipherSuites() {
		
		println("");
		println("[Host supported server cipher suites]");
		
		
		try {
		
			IDVHost[] hosts = this.dvHosts;
			
			if( hosts != null ) {
				
				IDVCipherSuite[] ciphers = eng.getCipherSuites();
				HashMap<String, String> tmap = new HashMap<String, String>();
		
				for( IDVCipherSuite cipher : ciphers ) {
					
					StringBuffer buff = new StringBuffer();
					buff.append( cipher.getSuiteName());
					buff.append( " (" ); 
					buff.append( cipher.getStrengthEvaluation() );
					buff.append( ',' );
					buff.append( cipher.getHandshakeProtocol() );
					buff.append( ')');
					println( buff.toString() );
					tmap.put(cipher.getSuiteName(), cipher.getStrengthEvaluation());
					
				}
			
			} else {
				
				println( "Problem fetching host ciphersuites.  See log for details." );
	        	logger.error("Problem processing server ciphers. err=hosts null");
				
			}
		
		} catch (Exception e) {
        	println("Problem processing server ciphers. err="+e.getMessage() );
			println("");
        	logger.error("Problem processing server ciphers. err="+e.getMessage(),e);
		}	
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolettools.api.IDVPrint#printServerCertificateChain()
	 */
	public void printServerCertificateChain() {
		
		println( "[Server certificate chain]" );
		
		StringBuffer buff = new StringBuffer();
		
		println("Chain Summary, end-entity --> root" );
		
        IDVX509Certificate[] certs;
        
		try {
			certs = dvCert.getCertificateChain();			
			boolean firstcert = true; 
			int n=0;
			IDVX509Certificate last_cert = null;
			
			for( IDVX509Certificate ldvCert: certs ) {

	        	
				if( ldvCert.isSelfSignedCertificate() ) {
					break;
				}
	        	
				println(buff.toString()+"|" ); 
				println(buff.toString()+"|" );
				
				StringBuffer attributes = new StringBuffer();
				
				attributes.append("NODE"+n+"(");
				
				if( firstcert ) {
					attributes.append("End-Entity ");
				} else {
					attributes.append("Intermediate CA ");
				}
				
				attributes.append(")--->");
				attributes.append("SubjectDN="+ldvCert.getSubjectDN()+" IssuerDN="+ldvCert.getIssuerDN());			
	  		    attributes.append(", "+ldvCert.getSigningAlgorithm()+"(Fingerprint)="+ldvCert.getCertificateFingerPrint());

				println(buff.toString()+attributes.toString() );
				
				firstcert = false;
				buff.append("   ");
				n++;
				last_cert = ldvCert;
	
	        }
	        
			println(buff.toString()+"|" ); 
			println(buff.toString()+"|" );
			buff.append( "NODE"+n+"(");
	                 		
			if( last_cert.isJavaRootCertificate() ) {
				buff.append("Java Root CA ");
			} else {
				buff.append("Self-Signed CA ");	
			}
			
			buff.append(")--->");
			buff.append("SubjectDN="+last_cert.getSubjectDN());
			

			buff.append(", "+last_cert.getSigningAlgorithm()+"(Fingerprint)="+last_cert.getCertificateFingerPrint());
			
			println(buff.toString() );

	        buff = new StringBuffer();

			println("" ); 
			println( "[Chain details]" );
	        
			int n1=0;
			for( IDVX509Certificate ldvCert: certs ) {
				println("[NODE"+n1+"] ");
				printX509Certificate(ldvCert);
				n1++;
			}
				
		} catch (Exception e) {
			println("Problem fetching certificates. err="+e.getMessage() );
			println("");
			logger.error("Problem fetching certificates. err="+e.getMessage(),e );
		}	
	
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolettools.api.IDVPrint#printServerCertificate()
	 */
	public void printServerCertificate() {
		
		println( "" );
		println( "[Server certificate information]" );
		
	    printTrustState( dvCert );
    		printX509Certificate( dvCert );        
	}
	
	/**
	 * Print a IDVX509Certificate instance.
	 * @param ldvCert Host certificate to print
	 */
	private final void printX509Certificate( IDVX509Certificate ldvCert ) {

		logger.trace(ldvCert.toString());
		
		String not_before = ldvCert.getNotValidBefore();
		String not_after = ldvCert.getNotValidAfter();
		
		ValidState validity_state = ldvCert.getValidityState();
		
		if (validity_state == IDVX509Certificate.ValidState.VALID){
			println( "Validity Check=VALID, certificate valid between "+not_before+" and "+not_after );
		} else if(validity_state == IDVX509Certificate.ValidState.NOT_YET_VALID){
			println( "Validity Check=>>>NOT YET VALID<<<, certificate valid between "+not_before+" and "+not_after );
		} else if(validity_state == IDVX509Certificate.ValidState.EXPIRED){
			println( "Validity Check=>>>EXPIRED<<<, certificate valid between "+not_before+" and "+not_after );
		} 
		
		String subject_dn = ldvCert.getSubjectDN();
		String issuer_dn = ldvCert.getIssuerDN();
		String serial_number = ldvCert.getCertificateSerialNumber().toString();
		String signature_algo = ldvCert.getSigningAlgorithm();
		String signature_algo_oid = ldvCert.getSigningAlgorithmOID();
		String certificate_ver = Integer.toString(ldvCert.getCertificateVersion());
		println( "SubjectDN="+subject_dn );
    	println( "IssuerDN="+issuer_dn );
    	println( "Serial Number="+serial_number );     	
    	println( "Signature Algorithm="+signature_algo);
    	println( "Signature Algorithm OID="+signature_algo_oid );
    	println( "Certificate Version ="+certificate_ver );
		
		String digest_algo = signature_algo.substring(0,signature_algo.indexOf("with"));
		String fingerprint = ldvCert.getCertificateFingerPrint();
		println(digest_algo+"(Fingerprint)="+fingerprint);
			
    	println( "Non-critical OIDs" );
    	printNonCritOIDs( ldvCert);
        	
    	println( "Critical OIDs" );
    	printCritOIDs( ldvCert);     	
        	
        println( "" );
		
}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolettools.api.IDVPrint#printTrustState()
	 */
	private void printTrustState( IDVX509Certificate ldvCert) {
		
		String trust_state = "<ERROR>";
		//TODO
		logger.error("ldvCert="+ldvCert+" ldvCert.getTrustState()="+ldvCert.getTrustState() );
		if( ldvCert.getTrustState() == IDVX509Certificate.TrustState.TRUSTED ) {
			trust_state="TRUSTED";
		}else if(ldvCert.getTrustState() == IDVX509Certificate.TrustState.UNKNOWN ) {
			trust_state="UNKNOWN";		
		}else if(ldvCert.getTrustState() == IDVX509Certificate.TrustState.UNTRUSTED ) {
			trust_state="UNTRUSTED";					
		}
		
		StringBuffer buff = new StringBuffer();
		buff.append("Trusted State=");
		boolean trusted = trust_state.equals(IDVX509Certificate.TrustState.TRUSTED);
		
		if( trusted ) {
			buff.append("trusted");
		}else{
			buff.append(">>>");
			buff.append(trust_state);
			buff.append("<<<");
		}
		println(buff.toString());
	
		
}
	
	/**
	 * Print a list of non-critical OIDs.
	 * @param ldvCert Host certificate
	 */
	private final void printNonCritOIDs(IDVX509Certificate ldvCert ) {
		
		String[] keys = ldvCert.getNonCritOIDProperties();
		
		for( String key : keys ) {
			String value = ldvCert.getNonCritPropertyValue(key);
			println( key +"="+value);
		}
		
}
	
	/**
	 * Print a list of critical OIDs.
	 * @param ldvCert Host certificate
	 */
	private final void printCritOIDs( IDVX509Certificate ldvCert) {
		
		String[] keys = ldvCert.getCritOIDProperties();
		
		for( String key : keys ) {
			String value = ldvCert.getCritPropertyValue(key);
			println( key +"="+value);
		}
		
	}
	
	private final void printServerAnalysis() {
	
		println("");
		println("[Server Analysis]");
		
		try {
		
			println( "MINIMAL_ENCRYPTION_STRENGTH="+eng.getPropertyValue("MINIMAL_ENCRYPTION_STRENGTH"));
			println( "ACHIEVABLE_ENCRYPTION_STRENGTH="+eng.getPropertyValue("ACHIEVABLE_ENCRYPTION_STRENGTH"));
			println( "BEAST_VULNERABLE="+eng.getPropertyValue("BEAST_VULNERABLE"));
			println( "CRIME_VULNERABLE="+eng.getPropertyValue("CRIME_VULNERABLE"));
			println( "FREAK_VULNERABLE="+eng.getPropertyValue("FREAK_VULNERABLE"));
			println( "ROBOT_VULNERABLE="+eng.getPropertyValue("ROBOT_VULNERABLE"));
			
		} catch( DVException e ) {
			String err = "Error performing server analysis="
					+ e.getMessage();
			println(err);
			logger.error(err, e);
		}
			
			
	}
	
	/**
	 * Execute sections of a scan report. Set the status bar message on each
	 * step for the user
	 */
	protected void doInBackground() throws Exception {

		if (bHeader) {

			setStatusBarMessage("Working on Report Header");

			printReportHeader();

		}

		if (bWriteCertificate) {

			setStatusBarMessage("Writing certificate to disk");

			try {
				eng.writeCertificate(filename);
			} catch (DVException e) {
				String err = "Error writing certificate to disk. msg="
						+ e.getMessage();
				println(err);
				logger.error(err, e);
			}

		}

//		if (bReadCertificate) {
//
//			setStatusBarMessage("Reading certificate from disk");
//
//			printCertificate(filename);
//
//		}

		if (bHostSection) {

			setStatusBarMessage("Working on Host Information");

			printHostInformation();

		}

// Removed for DV Beta 5.  See notes on printHostHttpResponseHeaders();
//		if (bHTTPResponseSection) {
//
//			setStatusBarMessage("Working on Host HTTP Response Headers");
//
//			printHostHttpResponseHeaders();
//
//		}

		if (bConnectionSection) {

			setStatusBarMessage("Working on Connection Characteristics");

			printConnectionCharacteristics();

		}

		if (bCiperSuitSection) {

			setStatusBarMessage("Working on Supported Cipher Suites");

			printSupportedCipherSuites();

		}

		if (bServerCertficateSection) {

			setStatusBarMessage("Working on Server Certificate");

			printServerCertificate();

		}

		if (bCertChainSection) {

			setStatusBarMessage("Working on Server Certificate Chain");

			printServerCertificateChain();

		}

		 if( bServerAnalysisSection ) {
		
			 setStatusBarMessage("Working on Server Analysis");
		
		 	 printServerAnalysis();
		
		 }
	}

}
