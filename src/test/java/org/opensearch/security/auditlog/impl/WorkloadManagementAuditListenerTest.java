/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security.auditlog.impl;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.Test;

import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.auditlog.AuditLog.Origin;
import org.opensearch.security.auditlog.AuditTestUtils;
import org.opensearch.security.auditlog.config.AuditConfig;
import org.opensearch.security.auditlog.integration.TestAuditlogImpl;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.AbstractSecurityUnitTest;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.wlm.WorkloadGroupActionNotifier;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class WorkloadManagementAuditListenerTest {

    private static ClusterService mockClusterService() {
        ClusterService clusterService = mock(ClusterService.class);
        DiscoveryNode node = mock(DiscoveryNode.class);
        when(clusterService.localNode()).thenReturn(node);
        when(clusterService.getClusterName()).thenReturn(new ClusterName("test"));
        when(node.getHostAddress()).thenReturn("127.0.0.1");
        when(node.getHostName()).thenReturn("localhost");
        when(node.getName()).thenReturn("node");
        when(node.getId()).thenReturn("id");
        return clusterService;
    }

    @Test
    public void workloadManagementAuditIsDisabledByDefault() {
        assertTrue(AuditConfig.from(Settings.EMPTY).getFilter().getDisabledCategories().contains(AuditCategory.WORKLOAD_MANAGEMENT_ACTION));
    }

    @Test
    public void respectsAuditCategoryFilters() throws Exception {
        ClusterService clusterService = mock(ClusterService.class);
        Settings settings = Settings.builder()
            .put("plugins.security.audit.type", TestAuditlogImpl.class.getName())
            .put(ConfigConstants.SECURITY_AUDIT_CONFIG_DISABLED_CATEGORIES, "NONE")
            .build();
        try (
            AuditLogImpl auditLog = (AuditLogImpl) AuditTestUtils.createAuditLog(
                settings,
                null,
                null,
                AbstractSecurityUnitTest.MOCK_POOL,
                null,
                clusterService
            )
        ) {
            assertTrue(auditLog.isWorkloadManagementAuditEnabled(null, Origin.REST));
            assertTrue(auditLog.isWorkloadManagementAuditEnabled(null, Origin.TRANSPORT));
            // A cancellation has no origin; it stays enabled while either layer is enabled.
            assertTrue(auditLog.isWorkloadManagementAuditEnabled(null, null));
            auditLog.getFilter().setDisabledRestCategories(List.of("WORKLOAD_MANAGEMENT_ACTION"));
            assertFalse(auditLog.isWorkloadManagementAuditEnabled(null, Origin.REST));
            assertTrue(auditLog.isWorkloadManagementAuditEnabled(null, Origin.TRANSPORT));
            auditLog.getFilter().setDisabledCategories(List.of("WORKLOAD_MANAGEMENT_ACTION"));
            assertFalse(auditLog.isWorkloadManagementAuditEnabled(null, null));
            assertFalse(auditLog.isWorkloadManagementAuditEnabled(null, Origin.TRANSPORT));
        }
    }

    @Test
    public void rejectionCarriesResourceAttributionAndNoTaskId() throws Exception {
        WorkloadGroupActionNotifier notifier = new WorkloadGroupActionNotifier();
        AuditLogImpl auditLog = mock(AuditLogImpl.class);
        ThreadPool threadPool = mock(ThreadPool.class);
        ThreadContext context = new ThreadContext(Settings.EMPTY);
        when(threadPool.getThreadContext()).thenReturn(context);
        context.putTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN, Origin.REST.toString());
        context.putTransient(ConfigConstants.SECURITY_AUDIT_REQUEST_ID, "req-1");
        when(auditLog.isWorkloadManagementAuditEnabled(isNull(), eq(Origin.REST))).thenReturn(true);

        CountDownLatch recorded = new CountDownLatch(1);
        AtomicReference<AuditMessage> captured = new AtomicReference<>();
        doAnswer(invocation -> {
            captured.set(invocation.getArgument(0));
            recorded.countDown();
            return null;
        }).when(auditLog).logWorkloadManagementAction(any());

        try (
            WorkloadManagementAuditListener listener = new WorkloadManagementAuditListener(
                notifier,
                auditLog,
                mockClusterService(),
                threadPool
            )
        ) {
            notifier.notifyRejected("group-1", "ENFORCED", "CPU", 0.8, 0.95);
            assertTrue(recorded.await(10, TimeUnit.SECONDS));
        }

        AuditMessage message = captured.get();
        assertEquals("REJECTED", message.getAsMap().get(AuditMessage.WLM_ACTION));
        assertEquals("group-1", message.getAsMap().get(AuditMessage.WLM_WORKLOAD_GROUP_ID));
        assertEquals("ENFORCED", message.getAsMap().get(AuditMessage.WLM_RESILIENCY_MODE));
        assertEquals("CPU", message.getAsMap().get(AuditMessage.WLM_RESOURCE_TYPE));
        assertEquals(0.8, (Double) message.getAsMap().get(AuditMessage.WLM_RESOURCE_THRESHOLD), 0.0);
        assertEquals(0.95, (Double) message.getAsMap().get(AuditMessage.WLM_RESOURCE_USAGE), 0.0);
        // No task exists at admission.
        assertNull(message.getAsMap().get(AuditMessage.WLM_TASK_ID));
        assertEquals("req-1", message.getAsMap().get(AuditMessage.REQUEST_ID));
    }

    @Test
    public void cancellationCarriesTaskIdAndNoResourceAttribution() throws Exception {
        WorkloadGroupActionNotifier notifier = new WorkloadGroupActionNotifier();
        AuditLogImpl auditLog = mock(AuditLogImpl.class);
        ThreadPool threadPool = mock(ThreadPool.class);
        // A cancellation is raised from the workload management scheduler, so the context is empty.
        when(threadPool.getThreadContext()).thenReturn(new ThreadContext(Settings.EMPTY));
        when(auditLog.isWorkloadManagementAuditEnabled(isNull(), isNull())).thenReturn(true);

        CountDownLatch recorded = new CountDownLatch(1);
        AtomicReference<AuditMessage> captured = new AtomicReference<>();
        doAnswer(invocation -> {
            captured.set(invocation.getArgument(0));
            recorded.countDown();
            return null;
        }).when(auditLog).logWorkloadManagementAction(any());

        try (
            WorkloadManagementAuditListener listener = new WorkloadManagementAuditListener(
                notifier,
                auditLog,
                mockClusterService(),
                threadPool
            )
        ) {
            notifier.notifyCancelled("group-1", 42L);
            assertTrue(recorded.await(10, TimeUnit.SECONDS));
        }

        AuditMessage message = captured.get();
        assertEquals("CANCELLED", message.getAsMap().get(AuditMessage.WLM_ACTION));
        assertEquals("group-1", message.getAsMap().get(AuditMessage.WLM_WORKLOAD_GROUP_ID));
        assertEquals(42L, message.getAsMap().get(AuditMessage.WLM_TASK_ID));
        assertNull(message.getAsMap().get(AuditMessage.WLM_RESOURCE_TYPE));
        assertNull(message.getAsMap().get(AuditMessage.WLM_RESOURCE_THRESHOLD));
        assertNull(message.getAsMap().get(AuditMessage.WLM_RESOURCE_USAGE));
        // Nothing correlates a cancellation to its request today; see the PR description.
        assertNull(message.getAsMap().get(AuditMessage.REQUEST_ID));
    }

    @Test
    public void doesNotBlockWorkloadManagementWhenAuditQueueIsFull() throws Exception {
        WorkloadGroupActionNotifier notifier = new WorkloadGroupActionNotifier();
        AuditLogImpl auditLog = mock(AuditLogImpl.class);
        ThreadPool threadPool = mock(ThreadPool.class);
        when(auditLog.isWorkloadManagementAuditEnabled(isNull(), eq(Origin.REST))).thenReturn(true);
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        doAnswer(invocation -> {
            started.countDown();
            assertTrue(release.await(10, TimeUnit.SECONDS));
            return null;
        }).when(auditLog).logWorkloadManagementAction(any());

        ThreadContext context = new ThreadContext(Settings.EMPTY);
        when(threadPool.getThreadContext()).thenReturn(context);
        context.putTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN, Origin.REST.toString());
        try (
            WorkloadManagementAuditListener listener = new WorkloadManagementAuditListener(
                notifier,
                auditLog,
                mockClusterService(),
                threadPool
            )
        ) {
            try {
                notifier.notifyRejected("group-1", "ENFORCED", "CPU", 0.8, 0.95);
                assertTrue(started.await(10, TimeUnit.SECONDS));
                for (int i = 0; i < 300; i++) {
                    notifier.notifyRejected("group-1", "ENFORCED", "CPU", 0.8, 0.95);
                }
                assertTrue(listener.getDroppedEvents() > 0);
            } finally {
                release.countDown();
            }
        }
        verify(auditLog, atLeastOnce()).logWorkloadManagementAction(any());
    }
}
