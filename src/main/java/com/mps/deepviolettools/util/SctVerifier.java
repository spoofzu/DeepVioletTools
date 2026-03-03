package com.mps.deepviolettools.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mps.deepviolet.util.X509Extensions;
import com.mps.deepviolet.util.X509Extensions.SignedCertificateTimestamp;

/**
 * Verifies SCT (Signed Certificate Timestamp) signatures per RFC 6962.
 *
 * @author Milton Smith
 */
public class SctVerifier {

	private static final Logger logger = LoggerFactory.getLogger(SctVerifier.class);

	/** SCT list extension OID */
	private static final String OID_SCT_LIST = "1.3.6.1.4.1.11129.2.4.2";

	public enum SctStatus {
		VALID, INVALID, UNKNOWN_LOG, VERIFICATION_ERROR
	}

	public record SctResult(SctStatus status, String message) {}

	/**
	 * Verify all embedded SCTs for the certificate at the given URL.
	 *
	 * @param url       target server URL
	 * @param lookup    CT log lookup with public keys
	 * @return map of Base64 LogID to verification result, empty on failure
	 */
	public static Map<String, SctResult> verifyEmbeddedScts(URL url, CTLogLookup lookup) {
		Map<String, SctResult> results = new HashMap<>();
		try {
			X509Certificate[] chain = fetchCertificateChain(url);
			if (chain == null || chain.length == 0) {
				logger.warn("Could not fetch certificate chain for SCT verification");
				return results;
			}

			X509Certificate leaf = chain[0];
			List<SignedCertificateTimestamp> scts = X509Extensions.getScts(leaf);
			if (scts == null || scts.isEmpty()) {
				return results;
			}

			// Need issuer to compute issuer key hash for precertificate entries
			if (chain.length < 2) {
				for (SignedCertificateTimestamp sct : scts) {
					results.put(sct.getLogIdBase64(),
							new SctResult(SctStatus.VERIFICATION_ERROR, "issuer certificate unavailable"));
				}
				return results;
			}

			X509Certificate issuer = chain[1];
			byte[] issuerKeyHash = computeIssuerKeyHash(issuer);
			byte[] tbsWithoutSct = removeSctExtension(leaf.getTBSCertificate());

			for (SignedCertificateTimestamp sct : scts) {
				results.put(sct.getLogIdBase64(), verifySingleSct(sct, issuerKeyHash, tbsWithoutSct, lookup));
			}
		} catch (Exception e) {
			logger.warn("SCT verification failed: {}", e.getMessage());
		}
		return results;
	}

	/**
	 * Verify a single SCT signature.
	 */
	private static SctResult verifySingleSct(SignedCertificateTimestamp sct,
			byte[] issuerKeyHash, byte[] tbsWithoutSct, CTLogLookup lookup) {
		try {
			CTLogLookup.CTLogInfo info = lookup.lookup(sct.getLogIdBase64());
			if (info == null) {
				return new SctResult(SctStatus.UNKNOWN_LOG, "unknown log");
			}

			PublicKey pubKey = info.getPublicKey();
			if (pubKey == null) {
				return new SctResult(SctStatus.VERIFICATION_ERROR, "key error");
			}

			String algorithm = mapSignatureAlgorithm(sct.hashAlgorithm, sct.signatureAlgorithm);
			if (algorithm == null) {
				return new SctResult(SctStatus.VERIFICATION_ERROR, "unsupported algorithm");
			}

			byte[] signedData = buildSignedData(sct, issuerKeyHash, tbsWithoutSct);

			Signature sig = Signature.getInstance(algorithm);
			sig.initVerify(pubKey);
			sig.update(signedData);

			if (sig.verify(sct.signature)) {
				return new SctResult(SctStatus.VALID, "VALID");
			} else {
				return new SctResult(SctStatus.INVALID, "INVALID");
			}
		} catch (Exception e) {
			logger.debug("SCT verification error for log {}: {}", sct.getLogIdBase64(), e.getMessage());
			return new SctResult(SctStatus.VERIFICATION_ERROR, "verification error");
		}
	}

	/**
	 * Build the signed data structure per RFC 6962 Section 3.2.
	 *
	 * <pre>
	 * digitally-signed struct {
	 *   Version sct_version;             // 1 byte
	 *   SignatureType signature_type;     // 1 byte (0 = certificate_timestamp)
	 *   uint64 timestamp;                // 8 bytes
	 *   LogEntryType entry_type;         // 2 bytes (1 = precert_entry)
	 *   PreCert:
	 *     opaque issuer_key_hash[32];    // SHA-256 of issuer's SubjectPublicKeyInfo
	 *     opaque tbs_certificate<1..2^24-1>; // TBSCertificate with SCT extension removed
	 *   CtExtensions extensions;         // 2-byte length + data
	 * }
	 * </pre>
	 */
	private static byte[] buildSignedData(SignedCertificateTimestamp sct,
			byte[] issuerKeyHash, byte[] tbsWithoutSct) throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();

		// sct_version = v1 (0)
		out.write(0x00);
		// signature_type = certificate_timestamp (0)
		out.write(0x00);
		// timestamp (8 bytes, big-endian)
		ByteBuffer buf = ByteBuffer.allocate(8);
		buf.putLong(sct.timestamp);
		out.write(buf.array());
		// entry_type = precert_entry (1)
		out.write(0x00);
		out.write(0x01);
		// issuer_key_hash (32 bytes)
		out.write(issuerKeyHash);
		// tbs_certificate length (3 bytes) + data
		out.write((tbsWithoutSct.length >> 16) & 0xFF);
		out.write((tbsWithoutSct.length >> 8) & 0xFF);
		out.write(tbsWithoutSct.length & 0xFF);
		out.write(tbsWithoutSct);
		// extensions length (2 bytes) + data
		byte[] extensions = sct.extensions != null ? sct.extensions : new byte[0];
		out.write((extensions.length >> 8) & 0xFF);
		out.write(extensions.length & 0xFF);
		out.write(extensions);

		return out.toByteArray();
	}

	/**
	 * SHA-256 hash of the issuer's SubjectPublicKeyInfo DER encoding.
	 */
	private static byte[] computeIssuerKeyHash(X509Certificate issuer) throws Exception {
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		return digest.digest(issuer.getPublicKey().getEncoded());
	}

	/**
	 * Map TLS hash/signature algorithm codes to Java Signature algorithm names.
	 */
	private static String mapSignatureAlgorithm(int hashAlgorithm, int signatureAlgorithm) {
		// hashAlgorithm: 4 = SHA-256, 5 = SHA-384, 6 = SHA-512
		// signatureAlgorithm: 1 = RSA, 3 = ECDSA
		if (hashAlgorithm == 4 && signatureAlgorithm == 3) {
			return "SHA256withECDSA";
		}
		if (hashAlgorithm == 4 && signatureAlgorithm == 1) {
			return "SHA256withRSA";
		}
		if (hashAlgorithm == 5 && signatureAlgorithm == 3) {
			return "SHA384withECDSA";
		}
		if (hashAlgorithm == 5 && signatureAlgorithm == 1) {
			return "SHA384withRSA";
		}
		return null;
	}

	/**
	 * Fetch the server's X509 certificate chain via TLS.
	 * Uses the already-installed default SSLContext (trust-all).
	 */
	private static X509Certificate[] fetchCertificateChain(URL url) {
		int port = url.getPort() > 0 ? url.getPort() : 443;
		try {
			SSLSocketFactory factory = SSLContext.getDefault().getSocketFactory();
			// Strip IPv6 brackets — url.getHost() returns "[::1]" for IPv6 URLs
			// but createSocket() expects the bare address "::1"
			String host = TargetParser.stripBrackets(url.getHost());
			try (SSLSocket socket = (SSLSocket) factory.createSocket(host, port)) {
				socket.setSoTimeout(15_000);
				socket.startHandshake();
				java.security.cert.Certificate[] certs = socket.getSession().getPeerCertificates();
				X509Certificate[] x509Certs = new X509Certificate[certs.length];
				for (int i = 0; i < certs.length; i++) {
					x509Certs[i] = (X509Certificate) certs[i];
				}
				return x509Certs;
			}
		} catch (Exception e) {
			logger.warn("Failed to fetch certificate chain from {}: {}", url.getHost(), e.getMessage());
			return null;
		}
	}

	/**
	 * Remove the SCT list extension (OID 1.3.6.1.4.1.11129.2.4.2) from a
	 * DER-encoded TBSCertificate. This is required for precertificate
	 * signature verification per RFC 6962.
	 *
	 * The TBSCertificate is a SEQUENCE containing fields. The last field
	 * tagged [3] (context-specific, constructed) holds the extensions
	 * SEQUENCE. We iterate extensions and remove the SCT list extension,
	 * rebuilding the DER with recalculated lengths.
	 */
	static byte[] removeSctExtension(byte[] tbsCertDer) throws IOException {
		// Parse outer SEQUENCE
		int[] outerTag = readTagAndLength(tbsCertDer, 0);
		// outerTag[0] = tag, outerTag[1] = length, outerTag[2] = offset of content

		int pos = outerTag[2]; // start of SEQUENCE content
		int outerEnd = outerTag[2] + outerTag[1]; // end of SEQUENCE content

		// Walk through TBSCertificate fields to find the [3] extensions field
		ByteArrayOutputStream fieldsBeforeExt = new ByteArrayOutputStream();
		int extensionsFieldStart = -1;

		while (pos < outerEnd) {
			int[] fieldTag = readTagAndLength(tbsCertDer, pos);
			int fieldTotalLen = (fieldTag[2] - pos) + fieldTag[1]; // header + content length
			int nextPos = pos + fieldTotalLen;

			// Check for context-specific tag [3] (0xA3)
			int rawTag = tbsCertDer[pos] & 0xFF;
			if (rawTag == 0xA3) {
				extensionsFieldStart = pos;
				break;
			}

			// Copy this field as-is
			fieldsBeforeExt.write(tbsCertDer, pos, fieldTotalLen);
			pos = nextPos;
		}

		if (extensionsFieldStart < 0) {
			// No extensions field found; return as-is
			return tbsCertDer;
		}

		// Parse the [3] wrapper
		int[] extFieldTag = readTagAndLength(tbsCertDer, extensionsFieldStart);
		int extContentStart = extFieldTag[2];

		// Inside [3] is a SEQUENCE of extensions
		int[] extSeqTag = readTagAndLength(tbsCertDer, extContentStart);
		int extSeqContentStart = extSeqTag[2];
		int extSeqContentEnd = extSeqTag[2] + extSeqTag[1];

		// Iterate individual Extension SEQUENCEs, skipping the SCT one
		ByteArrayOutputStream filteredExtensions = new ByteArrayOutputStream();
		int ePos = extSeqContentStart;
		boolean found = false;

		while (ePos < extSeqContentEnd) {
			int[] extTag = readTagAndLength(tbsCertDer, ePos);
			int extTotalLen = (extTag[2] - ePos) + extTag[1];
			int nextEPos = ePos + extTotalLen;

			// Check if this extension contains the SCT OID
			if (containsSctOid(tbsCertDer, ePos, extTotalLen)) {
				found = true;
			} else {
				filteredExtensions.write(tbsCertDer, ePos, extTotalLen);
			}

			ePos = nextEPos;
		}

		if (!found) {
			// SCT extension not found; return as-is
			return tbsCertDer;
		}

		// Rebuild: fields before extensions + [3] { SEQUENCE { filtered extensions } }
		byte[] filteredExtBytes = filteredExtensions.toByteArray();
		byte[] innerSeq = wrapDer(0x30, filteredExtBytes); // SEQUENCE of extensions
		byte[] extField = wrapDer(0xA3, innerSeq);         // [3] wrapper

		ByteArrayOutputStream newContent = new ByteArrayOutputStream();
		newContent.write(fieldsBeforeExt.toByteArray());
		newContent.write(extField);

		// Wrap in outer SEQUENCE
		return wrapDer(0x30, newContent.toByteArray());
	}

	/**
	 * Check if a DER-encoded Extension SEQUENCE contains the SCT list OID.
	 */
	private static boolean containsSctOid(byte[] data, int offset, int length) {
		// The SCT OID in DER: 06 0A 2B 06 01 04 01 D6 79 02 04 02
		// This is: 1.3.6.1.4.1.11129.2.4.2
		byte[] sctOidDer = {
			0x06, 0x0A,
			0x2B, 0x06, 0x01, 0x04, 0x01, (byte) 0xD6, 0x79, 0x02, 0x04, 0x02
		};

		int end = offset + length - sctOidDer.length;
		for (int i = offset; i <= end; i++) {
			boolean match = true;
			for (int j = 0; j < sctOidDer.length; j++) {
				if (data[i + j] != sctOidDer[j]) {
					match = false;
					break;
				}
			}
			if (match) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Read a DER tag and length at the given offset.
	 *
	 * @return int[3]: [tag, content-length, content-offset]
	 */
	static int[] readTagAndLength(byte[] data, int offset) throws IOException {
		if (offset >= data.length) {
			throw new IOException("DER: unexpected end of data at offset " + offset);
		}
		int tag = data[offset] & 0xFF;
		int pos = offset + 1;

		if (pos >= data.length) {
			throw new IOException("DER: unexpected end of data reading length");
		}
		int firstLenByte = data[pos] & 0xFF;
		pos++;

		int length;
		if (firstLenByte < 0x80) {
			// Short form
			length = firstLenByte;
		} else {
			// Long form
			int numLenBytes = firstLenByte & 0x7F;
			if (numLenBytes == 0 || numLenBytes > 4) {
				throw new IOException("DER: unsupported length encoding: " + numLenBytes + " bytes");
			}
			length = 0;
			for (int i = 0; i < numLenBytes; i++) {
				if (pos >= data.length) {
					throw new IOException("DER: unexpected end of data reading length bytes");
				}
				length = (length << 8) | (data[pos] & 0xFF);
				pos++;
			}
		}

		return new int[] { tag, length, pos };
	}

	/**
	 * Encode a DER length value.
	 */
	private static byte[] encodeDerLength(int length) {
		if (length < 0x80) {
			return new byte[] { (byte) length };
		} else if (length < 0x100) {
			return new byte[] { (byte) 0x81, (byte) length };
		} else if (length < 0x10000) {
			return new byte[] { (byte) 0x82, (byte) (length >> 8), (byte) length };
		} else if (length < 0x1000000) {
			return new byte[] { (byte) 0x83, (byte) (length >> 16), (byte) (length >> 8), (byte) length };
		} else {
			return new byte[] { (byte) 0x84, (byte) (length >> 24), (byte) (length >> 16),
					(byte) (length >> 8), (byte) length };
		}
	}

	/**
	 * Wrap content bytes with a DER tag and length.
	 */
	private static byte[] wrapDer(int tag, byte[] content) {
		byte[] lenBytes = encodeDerLength(content.length);
		byte[] result = new byte[1 + lenBytes.length + content.length];
		result[0] = (byte) tag;
		System.arraycopy(lenBytes, 0, result, 1, lenBytes.length);
		System.arraycopy(content, 0, result, 1 + lenBytes.length, content.length);
		return result;
	}
}
