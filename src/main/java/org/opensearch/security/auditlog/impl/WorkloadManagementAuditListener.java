/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security.auditlog.impl;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.auditlog.AuditLog.Origin;
import org.opensearch.security.filter.SecurityRestFilter;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.wlm.WorkloadGroupActionNotifier;

/**
 * Converts workload management actions to audit events off the thread that performed the action.
 *
 * <p>Two sources, with different context available:</p>
 * <ul>
 *   <li>A <b>rejection</b> is raised on the request's own thread while admitting a search, so the
 *       authenticated user, the origin and the request id are all present and the event correlates
 *       with that request's other audit records.</li>
 *   <li>A <b>cancellation</b> is raised from the workload management scheduler on the generic thread
 *       pool, not from the request. No user, origin or request id is available; the event carries the
 *       task id instead.</li>
 * </ul>
 *
 * <p>Workload management governs only {@code SearchTask} and {@code SearchShardTask}, so it never acts
 * on the audit sink's own index writes. No self-suppression marker is needed here.</p>
 */
public final class WorkloadManagementAuditListener implements AutoCloseable {
    private static final Logger log = LogManager.getLogger(WorkloadManagementAuditListener.class);
    private static final int QUEUE_CAPACITY = 256;
    private static final int MAX_LABEL_LENGTH = 256;

    private final WorkloadGroupActionNotifier notifier;
    private final AuditLogImpl auditLog;
    private final ClusterService clusterService;
    private final ThreadPool threadPool;
    private final ThreadPoolExecutor executor = new ThreadPoolExecutor(
        1,
        1,
        0,
        TimeUnit.MILLISECONDS,
        new ArrayBlockingQueue<>(QUEUE_CAPACITY)
    );
    private final AtomicBoolean closed = new AtomicBoolean();
    private final AtomicBoolean warnedAboutOversizedUser = new AtomicBoolean();
    private final AtomicLong droppedEvents = new AtomicLong();
    private final Consumer<WorkloadGroupActionNotifier.Action> listener = this::onAction;

    public WorkloadManagementAuditListener(
        WorkloadGroupActionNotifier notifier,
        AuditLogImpl auditLog,
        ClusterService clusterService,
        ThreadPool threadPool
    ) {
        this.notifier = notifier;
        this.auditLog = auditLog;
        this.clusterService = clusterService;
        this.threadPool = threadPool;
        notifier.addListener(listener);
    }

    private void onAction(WorkloadGroupActionNotifier.Action action) {
        if (closed.get()) {
            return;
        }
        ThreadContext context = threadPool.getThreadContext();
        User user = context.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        String userName = user == null ? null : user.getName();
        String originValue = context.getTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN);
        Origin origin = switch (originValue == null ? "" : originValue) {
            case "REST" -> Origin.REST;
            case "TRANSPORT" -> Origin.TRANSPORT;
            case "GRPC" -> Origin.GRPC;
            case "LOCAL" -> Origin.LOCAL;
            default -> null;
        };
        if (!auditLog.isWorkloadManagementAuditEnabled(userName, origin)) {
            return;
        }
        if (userName != null && userName.length() > MAX_LABEL_LENGTH) {
            if (warnedAboutOversizedUser.compareAndSet(false, true)) {
                log.warn("Skipping workload management audit events with oversized user names");
            }
            return;
        }
        String requestId = context.getTransient(ConfigConstants.SECURITY_AUDIT_REQUEST_ID);
        if (requestId == null) {
            String header = context.getHeader(Task.X_REQUEST_ID);
            requestId = header == null ? null : SecurityRestFilter.sanitizeRequestId(header);
        }
        final String finalRequestId = requestId == null || requestId.length() <= MAX_LABEL_LENGTH ? requestId : null;
        final String workloadGroupId = truncate(action.workloadGroupId());
        final String kind = action.kind().toString();
        final boolean rejected = action.kind() == WorkloadGroupActionNotifier.Kind.REJECTED;
        final String resiliencyMode = truncate(action.resiliencyMode());
        final String resourceType = truncate(action.resourceType());
        // A rejection has no task, and a cancellation has no resource attribution; see Action.
        final Double threshold = rejected ? action.threshold() : null;
        final Double observedUsage = rejected ? action.observedUsage() : null;
        final Long taskId = rejected ? null : action.taskId();
        try {
            executor.execute(() -> {
                try {
                    if (!auditLog.isWorkloadManagementAuditEnabled(userName, origin)) {
                        return;
                    }
                    AuditMessage message = new AuditMessage(AuditCategory.WORKLOAD_MANAGEMENT_ACTION, clusterService, origin, null);
                    message.addEffectiveUser(userName);
                    message.addRequestId(finalRequestId);
                    message.addWorkloadManagementDetails(
                        kind,
                        workloadGroupId,
                        resiliencyMode,
                        resourceType,
                        threshold,
                        observedUsage,
                        taskId
                    );
                    auditLog.logWorkloadManagementAction(message);
                } catch (RuntimeException e) {
                    log.error("Failed to record workload management audit event", e);
                }
            });
        } catch (RejectedExecutionException e) {
            if (!closed.get()) {
                long dropped = droppedEvents.incrementAndGet();
                if ((dropped & (dropped - 1)) == 0) {
                    log.warn("Dropped {} workload management audit events because the audit queue is full", dropped);
                }
            }
        }
    }

    private static String truncate(String value) {
        if (value == null || value.length() <= MAX_LABEL_LENGTH) {
            return value;
        }
        return value.substring(0, MAX_LABEL_LENGTH);
    }

    long getDroppedEvents() {
        return droppedEvents.get();
    }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        notifier.removeListener(listener);
        executor.shutdown();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                int dropped = executor.shutdownNow().size();
                log.warn("Dropped {} queued workload management audit events during shutdown", dropped);
            }
        } catch (InterruptedException e) {
            int dropped = executor.shutdownNow().size();
            log.warn("Interrupted while stopping workload management audit listener; dropped {} queued events", dropped);
            Thread.currentThread().interrupt();
        }
    }
}
