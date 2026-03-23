/*
 * Copyright (C) 2017-2026 Dominic Heutelbeck (dominic@heutelbeck.com)
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package io.sapl.benchmark3;

import io.sapl.api.pdp.AuthorizationDecision;
import io.sapl.api.pdp.AuthorizationSubscription;
import io.sapl.api.pdp.PolicyDecisionPoint;
import io.sapl.pdp.PolicyDecisionPointFactory;
import lombok.val;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;

/**
 * JMH benchmark for SAPL 3.0.0 embedded PDP.
 */
@State(Scope.Benchmark)
public class EmbeddedBenchmark {

    @Param({})
    public String policiesPath;

    private PolicyDecisionPoint pdp;
    private AuthorizationSubscription subscription;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        val subject = "{\"name\":\"alice\",\"roles\":[\"admin\"],\"department\":\"engineering\",\"clearanceLevel\":5}";
        subscription = AuthorizationSubscription.of(
                new com.fasterxml.jackson.databind.ObjectMapper().readTree(subject), "read", "document");
        pdp = PolicyDecisionPointFactory.filesystemPolicyDecisionPoint(policiesPath);
    }

    @TearDown(Level.Trial)
    public void tearDown() {
        if (pdp instanceof AutoCloseable closeable) {
            try {
                closeable.close();
            } catch (Exception ignored) {
                // cleanup only
            }
        }
    }

    @Benchmark
    public AuthorizationDecision decideFirst() {
        return pdp.decide(subscription).blockFirst();
    }

    @Benchmark
    public AuthorizationDecision decideOnce() {
        return pdp.decideOnce(subscription).block();
    }

}
