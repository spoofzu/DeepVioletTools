package com.mps.deepviolettools.model;

/**
 * Enumeration of draggable metadata elements that can appear on a
 * {@link com.mps.deepviolettools.ui.HostCard}.  Each constant carries a
 * human-readable display name (shown in the drag palette) and a property
 * key used for persistence.
 */
public enum CardMetaElement {

	GRADE("Grade", "grade"),
	SCORE("Score", "score"),
	HOSTNAME("Host Name", "hostname"),
	IP("IP", "ip"),
	TLS_VERSION("TLS Version", "tlsVersion"),
	CIPHERS("Ciphers", "ciphers"),
	HEADERS("Headers", "headers"),
	CERT("Cert", "cert"),
	RISK_BARS("Risk Bars", "riskBars"),
	CERT_EXPIRY("Cert Expiry", "certExpiry"),
	KEY_INFO("Key Info", "keyInfo"),
	ISSUER("Issuer", "issuer"),
	SAN_COUNT("SANs", "sanCount"),
	REVOCATION("Revocation", "revocation");

	private final String displayName;
	private final String propertyKey;

	CardMetaElement(String displayName, String propertyKey) {
		this.displayName = displayName;
		this.propertyKey = propertyKey;
	}

	/** Human-readable label for the drag palette. */
	public String getDisplayName() {
		return displayName;
	}

	/** Property key used for persistence in {@code deepviolet.properties}. */
	public String getPropertyKey() {
		return propertyKey;
	}

	/**
	 * Look up an element by its property key.
	 *
	 * @param key the property key (e.g. "grade")
	 * @return the matching element, or null if not found
	 */
	public static CardMetaElement fromPropertyKey(String key) {
		for (CardMetaElement e : values()) {
			if (e.propertyKey.equals(key)) {
				return e;
			}
		}
		return null;
	}
}
