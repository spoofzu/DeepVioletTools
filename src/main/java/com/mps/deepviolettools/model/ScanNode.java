package com.mps.deepviolettools.model;

import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * Hierarchical node in the scan result tree. Each node carries its type
 * explicitly so renderers can style based on {@link NodeType} and
 * {@link #getLevel()} without regex classification.
 *
 * <p>Thread safety: children are stored in a {@link CopyOnWriteArrayList}
 * so the background scan thread can append while the EDT reads for
 * rendering.</p>
 *
 * @author Milton Smith
 */
public class ScanNode {

	/**
	 * Classification of a scan result node for styling purposes.
	 */
	public enum NodeType {
		/** Invisible root container (level 0) */
		ROOT,
		/** Section heading like [Host information] (level 1) */
		SECTION,
		/** Subsection label like "OCSP Check:" (level 2+) */
		SUBSECTION,
		/** Key=value data */
		KEY_VALUE,
		/** Notice/banner lines (***) */
		NOTICE,
		/** Warning lines (>>>) */
		WARNING,
		/** Plain text content */
		CONTENT,
		/** Blank separator line */
		BLANK
	}

	private final String key;
	private final String value;
	private final NodeType type;
	private final String severity;
	private ScanNode parent;
	private final List<ScanNode> children = new CopyOnWriteArrayList<>();

	private ScanNode(String key, String value, NodeType type) {
		this(key, value, type, null);
	}

	private ScanNode(String key, String value, NodeType type, String severity) {
		this.key = key;
		this.value = value;
		this.type = type;
		this.severity = severity;
	}

	// ---- static factory methods ----

	/** Create the invisible root container. */
	public static ScanNode createRoot() {
		return new ScanNode(null, null, NodeType.ROOT);
	}

	/** Create a section heading node (e.g. "Host information"). */
	public static ScanNode createSection(String name) {
		return new ScanNode(name, null, NodeType.SECTION);
	}

	/** Create a subsection label node (e.g. "OCSP Check"). */
	public static ScanNode createSubsection(String label) {
		return new ScanNode(label, null, NodeType.SUBSECTION);
	}

	/** Create a key=value data node. */
	public static ScanNode createKeyValue(String key, String value) {
		return new ScanNode(key, value, NodeType.KEY_VALUE);
	}

	/** Create a notice/banner node. */
	public static ScanNode createNotice(String text) {
		return new ScanNode(text, null, NodeType.NOTICE);
	}

	/** Create a warning node. */
	public static ScanNode createWarning(String text) {
		return new ScanNode(text, null, NodeType.WARNING);
	}

	/** Create a warning node with a risk severity level. */
	public static ScanNode createWarning(String text, String severity) {
		return new ScanNode(text, null, NodeType.WARNING, severity);
	}

	/** Create a plain content node. */
	public static ScanNode createContent(String text) {
		return new ScanNode(text, null, NodeType.CONTENT);
	}

	/** Create a blank separator node. */
	public static ScanNode createBlank() {
		return new ScanNode(null, null, NodeType.BLANK);
	}

	// ---- child-adder convenience methods (return the new child) ----

	/** Add a generic child node. Sets the child's parent. */
	public ScanNode addChild(ScanNode child) {
		child.parent = this;
		children.add(child);
		return child;
	}

	/** Add a section heading child. */
	public ScanNode addSection(String name) {
		return addChild(createSection(name));
	}

	/** Add a subsection label child. */
	public ScanNode addSubsection(String label) {
		return addChild(createSubsection(label));
	}

	/** Add a key=value data child. */
	public ScanNode addKeyValue(String key, String value) {
		return addChild(createKeyValue(key, value));
	}

	/** Add a notice/banner child. */
	public ScanNode addNotice(String text) {
		return addChild(createNotice(text));
	}

	/** Add a warning child. */
	public ScanNode addWarning(String text) {
		return addChild(createWarning(text));
	}

	/** Add a warning child with a risk severity level. */
	public ScanNode addWarning(String text, String severity) {
		return addChild(createWarning(text, severity));
	}

	/** Add a plain content child. */
	public ScanNode addContent(String text) {
		return addChild(createContent(text));
	}

	/** Add a blank separator child. */
	public ScanNode addBlank() {
		return addChild(createBlank());
	}

	// ---- accessors ----

	/** @return the key/label text (null for ROOT and BLANK) */
	public String getKey() {
		return key;
	}

	/** @return the value text (non-null only for KEY_VALUE nodes) */
	public String getValue() {
		return value;
	}

	/** @return the node type */
	public NodeType getType() {
		return type;
	}

	/** @return the risk severity level (null for non-risk warnings) */
	public String getSeverity() {
		return severity;
	}

	/** @return the parent node (null for root) */
	public ScanNode getParent() {
		return parent;
	}

	/** @return the child nodes (live, thread-safe list) */
	public List<ScanNode> getChildren() {
		return children;
	}

	/** @return true if this node has children */
	public boolean hasChildren() {
		return !children.isEmpty();
	}

	/**
	 * Compute the depth level from the root.
	 * ROOT=0, SECTION=1, data inside section=2, etc.
	 *
	 * @return depth level
	 */
	public int getLevel() {
		int level = 0;
		ScanNode p = parent;
		while (p != null) {
			level++;
			p = p.parent;
		}
		return level;
	}

	// ---- traversal ----

	/**
	 * Pre-order DFS walk over all nodes including root.
	 *
	 * @param visitor called for each node
	 */
	public void walk(Consumer<ScanNode> visitor) {
		visitor.accept(this);
		for (ScanNode child : children) {
			child.walk(visitor);
		}
	}

	/**
	 * Pre-order DFS walk that skips the ROOT node.
	 *
	 * @param visitor called for each visible (non-ROOT) node
	 */
	public void walkVisible(Consumer<ScanNode> visitor) {
		walk(node -> {
			if (node.type != NodeType.ROOT) {
				visitor.accept(node);
			}
		});
	}

	/**
	 * Remove SECTION children whose key matches any name in the given set.
	 * Used to filter the tree for display without affecting the scan data.
	 *
	 * @param sectionNames section titles to remove (e.g. "Host information")
	 */
	public void removeSections(Set<String> sectionNames) {
		children.removeIf(child ->
				child.type == NodeType.SECTION && sectionNames.contains(child.key));
	}
}
