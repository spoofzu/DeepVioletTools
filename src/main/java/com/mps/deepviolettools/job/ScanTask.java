package com.mps.deepviolettools.job;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicIntegerArray;
import java.util.function.BiConsumer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mps.deepviolet.api.DeepVioletException;
import com.mps.deepviolet.api.ISession.CIPHER_NAME_CONVENTION;
import com.mps.deepviolettools.model.ScanResult;
import com.mps.deepviolettools.model.ScanResult.HostResult;

/**
 * Orchestrates parallel scanning of multiple targets.
 * Runs on a background thread, distributing work across a configurable
 * number of worker threads. Each worker pulls targets from a shared
 * queue and reports per-worker status for the UI status bar.
 *
 * <p>Progress is reported via a callback with the current index
 * and target URL.</p>
 *
 * @author Milton Smith
 */
public class ScanTask implements Runnable {

	private static final Logger logger = LoggerFactory.getLogger(ScanTask.class);
	private static final Logger scanlog = LoggerFactory.getLogger("scanlog");

	private final String scanSessionId = UUID.randomUUID().toString();

	/**
	 * Tracks the state of a single worker thread for status bar display.
	 * Fields are volatile for cross-thread visibility from the EDT timer.
	 */
	public static class WorkerStatus {
		private final int workerId; // 1-based
		private volatile String phase = "idle";
		private volatile boolean active;
		private volatile UIBackgroundScanTask currentSubtask;
		private volatile String currentTarget;
		private volatile int targetIndex; // 1-based target number
		private volatile long startTimeMs;
		private volatile long finishTimeMs;

		public WorkerStatus(int workerId) {
			this.workerId = workerId;
		}

		public int getWorkerId() {
			return workerId;
		}

		public String getPhase() {
			return phase;
		}

		public boolean isActive() {
			return active;
		}

		public UIBackgroundScanTask getCurrentSubtask() {
			return currentSubtask;
		}

		public String getCurrentTarget() {
			return currentTarget;
		}

		public int getTargetIndex() {
			return targetIndex;
		}

		/** Called when a worker begins scanning a new target. */
		public void startTarget(String target, int targetIndex, UIBackgroundScanTask subtask) {
			this.currentTarget = target;
			this.targetIndex = targetIndex;
			this.currentSubtask = subtask;
			this.startTimeMs = System.currentTimeMillis();
			this.finishTimeMs = 0;
			this.phase = "Initializing";
			this.active = true;
		}

		/** Called when a worker finishes scanning a target. */
		public void finishTarget() {
			this.finishTimeMs = System.currentTimeMillis();
			long elapsed = finishTimeMs - startTimeMs;
			this.phase = "ready(" + elapsed + "ms)";
			this.active = false;
			this.currentSubtask = null;
		}

		/** Called when a worker has no more targets. */
		public void setIdle() {
			this.phase = "idle";
			this.active = false;
			this.currentSubtask = null;
			this.currentTarget = null;
		}
	}

	private final List<String> targetUrls;
	private final ScanResult result;
	private volatile boolean running;
	private volatile boolean cancelled;

	// Worker status array — one per active worker, created at scan start
	private volatile WorkerStatus[] workerStatuses;

	// Per-target state tracking for group progress display
	public static final int TARGET_NOT_STARTED = 0;
	public static final int TARGET_WORKING = 1;
	public static final int TARGET_FINISHED = 2;
	private volatile AtomicIntegerArray targetStates;

	// Thread-safe counters for parallel result tracking
	private final AtomicInteger completedCount = new AtomicInteger(0);
	private final AtomicInteger successCount = new AtomicInteger(0);
	private final AtomicInteger errorCount = new AtomicInteger(0);

	// Engine preferences to apply to each individual scan
	private boolean bRiskAssessmentSection = true;
	private boolean bHeader = false;
	private boolean bRuntimeEnvironmentSection = true;
	private boolean bHostSection = true;
	private boolean bHTTPResponseSection = true;
	private boolean bConnectionSection = true;
	private boolean bCipherSuiteSection = true;
	private boolean bCertChainSection = false;
	private boolean bSecurityHeadersSection = true;
	private boolean bRevocationSection = false;
	private boolean bTlsFingerprintSection = true;

	private boolean protocolSslv3 = false;
	private boolean protocolTls10 = false;
	private boolean protocolTls11 = false;
	private boolean protocolTls12 = true;
	private boolean protocolTls13 = true;

	private CIPHER_NAME_CONVENTION cipherConvention = CIPHER_NAME_CONVENTION.IANA;
	private int riskScale = 20;

	/** User risk rules YAML to propagate to each subtask. */
	private volatile String userRiskRulesYaml;

	private int workerThreadCount = 1;
	private long throttleDelayMs = 0;

	/** Callback: (currentIndex, currentTarget) */
	private BiConsumer<Integer, String> progressCallback;

	/** Callback when scan completes */
	private Runnable completionCallback;

	public ScanTask(List<String> targetUrls) {
		this.targetUrls = targetUrls;
		this.result = new ScanResult();
		this.result.setTotalTargets(targetUrls.size());
	}

	/** Apply engine preferences from FontPreferences. */
	public void applyPreferences(
			boolean riskAssessment, boolean runtimeEnvironment,
			boolean host,
			boolean httpResponse, boolean connection, boolean cipherSuites,
			boolean certChain, boolean securityHeaders, boolean revocation,
			boolean tlsFingerprint,
			boolean sslv3, boolean tls10, boolean tls11, boolean tls12, boolean tls13,
			CIPHER_NAME_CONVENTION convention, int scale) {
		this.bRiskAssessmentSection = riskAssessment;
		this.bHeader = true; // always included
		this.bRuntimeEnvironmentSection = runtimeEnvironment;
		this.bHostSection = host;
		this.bHTTPResponseSection = httpResponse;
		this.bConnectionSection = connection;
		this.bCipherSuiteSection = cipherSuites;
		this.bCertChainSection = certChain;
		this.bSecurityHeadersSection = securityHeaders;
		this.bRevocationSection = revocation;
		this.bTlsFingerprintSection = tlsFingerprint;
		this.protocolSslv3 = sslv3;
		this.protocolTls10 = tls10;
		this.protocolTls11 = tls11;
		this.protocolTls12 = tls12;
		this.protocolTls13 = tls13;
		this.cipherConvention = convention;
		this.riskScale = scale;
	}

	public void setProgressCallback(BiConsumer<Integer, String> callback) {
		this.progressCallback = callback;
	}

	public void setCompletionCallback(Runnable callback) {
		this.completionCallback = callback;
	}

	public void setWorkerThreadCount(int count) {
		this.workerThreadCount = Math.max(1, Math.min(10, count));
	}

	public void setThrottleDelayMs(long delayMs) {
		this.throttleDelayMs = Math.max(0, Math.min(10000, delayMs));
	}

	/**
	 * Set user risk rules YAML to propagate to each subtask.
	 *
	 * @param yaml the YAML content, or null to use system rules only
	 */
	public void setUserRiskRulesYaml(String yaml) {
		this.userRiskRulesYaml = yaml;
	}

	public ScanResult getResult() {
		return result;
	}

	public boolean isRunning() {
		return running;
	}

	/** Returns the worker status array. May be null before scan starts. */
	public WorkerStatus[] getWorkerStatuses() {
		return workerStatuses;
	}

	/** Returns the total number of targets in this scan. */
	public int getTargetCount() {
		return targetUrls.size();
	}

	/** Returns per-target state array. May be null before scan starts. */
	public AtomicIntegerArray getTargetStates() {
		return targetStates;
	}

	/**
	 * Returns the current target of the first active worker, for backward compatibility.
	 */
	public String getCurrentTarget() {
		WorkerStatus[] statuses = workerStatuses;
		if (statuses != null) {
			for (WorkerStatus ws : statuses) {
				if (ws.isActive()) return ws.getCurrentTarget();
			}
		}
		return null;
	}

	/**
	 * Returns the subtask of the first active worker, for backward compatibility.
	 */
	public UIBackgroundScanTask getCurrentSubtask() {
		WorkerStatus[] statuses = workerStatuses;
		if (statuses != null) {
			for (WorkerStatus ws : statuses) {
				if (ws.isActive()) return ws.getCurrentSubtask();
			}
		}
		return null;
	}

	/** @return the unique session ID for this multi-target scan */
	public String getScanSessionId() {
		return scanSessionId;
	}

	public void cancel() {
		this.cancelled = true;
	}

	@Override
	public void run() {
		running = true;
		long scanStartTime = System.currentTimeMillis();

		int effectiveWorkers = Math.min(workerThreadCount, targetUrls.size());
		scanlog.info("multi-target({}) Scan started targets={}, workers={}",
				scanSessionId, targetUrls.size(), effectiveWorkers);
		targetStates = new AtomicIntegerArray(targetUrls.size());
		ConcurrentLinkedQueue<Integer> indexQueue = new ConcurrentLinkedQueue<>();
		for (int i = 0; i < targetUrls.size(); i++) indexQueue.add(i);

		// Initialize worker statuses
		WorkerStatus[] statuses = new WorkerStatus[effectiveWorkers];
		for (int i = 0; i < effectiveWorkers; i++) {
			statuses[i] = new WorkerStatus(i + 1);
		}
		this.workerStatuses = statuses;

		ExecutorService executor = Executors.newFixedThreadPool(effectiveWorkers, r -> {
			Thread t = new Thread(r);
			t.setDaemon(true);
			return t;
		});

		try {
			List<Future<?>> futures = new ArrayList<>();
			for (int i = 0; i < effectiveWorkers; i++) {
				final WorkerStatus ws = statuses[i];
				futures.add(executor.submit(() -> workerLoop(ws, indexQueue)));
			}

			// Wait for all workers to complete
			for (Future<?> future : futures) {
				try {
					future.get();
				} catch (Exception e) {
					logger.error("Worker future failed: {}", e.getMessage(), e);
				}
			}
		} finally {
			executor.shutdown();
			result.setSuccessCount(successCount.get());
			result.setErrorCount(errorCount.get());

			// Set all workers idle
			for (WorkerStatus ws : statuses) {
				ws.setIdle();
			}

			String status = cancelled ? "cancelled" : "completed";
			long totalElapsed = System.currentTimeMillis() - scanStartTime;
			scanlog.info("multi-target({}) Scan completed status={}, success={}, errors={}, totalElapsed={}ms",
					scanSessionId, status, successCount.get(), errorCount.get(), totalElapsed);

			running = false;

			if (completionCallback != null) {
				completionCallback.run();
			}
		}
	}

	/**
	 * Worker loop — pulls targets from the shared queue and scans them.
	 */
	private void workerLoop(WorkerStatus status, ConcurrentLinkedQueue<Integer> indexQueue) {
		Integer idx;
		while (!cancelled && (idx = indexQueue.poll()) != null) {
			String target = targetUrls.get(idx);
			int targetNum = idx + 1; // 1-based for display
			if (progressCallback != null) {
				progressCallback.accept(completedCount.get(), target);
			}

			HostResult hostResult = new HostResult(target);

			try {
				URL url = new URL(target);
				UIBackgroundScanTask st = new UIBackgroundScanTask(url);

				// Apply engine preferences
				st.bMultiTargetMode = true;
				st.bRiskAssessmentSection = bRiskAssessmentSection;
				st.bHeader = bHeader;
				st.bRuntimeEnvironmentSection = bRuntimeEnvironmentSection;
				st.bHostSection = bHostSection;
				st.bHTTPResponseSection = bHTTPResponseSection;
				st.bConnectionSection = bConnectionSection;
				st.bCipherSuiteSection = bCipherSuiteSection;
				st.bCertChainSection = bCertChainSection;
				st.bSecurityHeadersSection = bSecurityHeadersSection;
				st.bRevocationSection = bRevocationSection;
				st.bTlsFingerprintSection = bTlsFingerprintSection;
				st.protocolSslv3 = protocolSslv3;
				st.protocolTls10 = protocolTls10;
				st.protocolTls11 = protocolTls11;
				st.protocolTls12 = protocolTls12;
				st.protocolTls13 = protocolTls13;
				st.setCipherConvention(cipherConvention);
				st.setRiskScale(riskScale);
				if (userRiskRulesYaml != null) {
					st.setUserRiskRulesYaml(userRiskRulesYaml);
				}

				// Start scanning
				targetStates.set(idx, TARGET_WORKING);
				status.startTarget(target, targetNum, st);
				st.start();

				// Block until completion, updating phase from subtask status
				while (st.isWorking()) {
					if (cancelled) {
						st.cancel();
						break;
					}
					String msg = st.getStatusBarMessage();
					if (msg != null) {
						status.phase = msg;
					}
					Thread.sleep(100);
				}

				if (cancelled) {
					hostResult.setErrorMessage("Scan cancelled");
					errorCount.incrementAndGet();
				} else {
					// Collect results
					hostResult.setRiskScore(st.getLastRiskScore());
					hostResult.setCiphers(st.getLastCipherSuites());
					hostResult.setSecurityHeaders(st.getLastSecurityHeaders());
					hostResult.setConnProperties(st.getLastConnProperties());
					hostResult.setHttpHeaders(st.getLastHttpHeaders());
					hostResult.setTlsFingerprint(st.getLastFingerprint());
					hostResult.setScanTree(st.getRoot());
					hostResult.setRuleContextMap(st.getLastRuleContextMap());
					successCount.incrementAndGet();
				}

			} catch (DeepVioletException e) {
				hostResult.setErrorMessage("DV error: " + e.getMessage());
				errorCount.incrementAndGet();
				logger.warn("Scan failed for {}: {}", target, e.getMessage());
			} catch (Exception e) {
				hostResult.setErrorMessage(e.getMessage());
				errorCount.incrementAndGet();
				logger.warn("Scan failed for {}: {}", target, e.getMessage());
			}

			result.addResult(hostResult);
			completedCount.incrementAndGet();
			targetStates.set(idx, TARGET_FINISHED);
			status.finishTarget();

			// Throttle delay between targets (if configured)
			if (throttleDelayMs > 0 && !cancelled) {
				try {
					Thread.sleep(throttleDelayMs);
				} catch (InterruptedException ie) {
					Thread.currentThread().interrupt();
					break;
				}
			}
		}

		// No more targets for this worker
		status.setIdle();
	}

	/** Start the scan on a new daemon thread. */
	public Thread start() {
		Thread t = new Thread(this, "ScanTask");
		t.setDaemon(true);
		t.start();
		return t;
	}
}
