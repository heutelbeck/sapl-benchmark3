/*
 * Copyright (C) 2017-2026 Dominic Heutelbeck (dominic@heutelbeck.com)
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package io.sapl.benchmark3;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

import lombok.val;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import org.openjdk.jmh.runner.options.TimeValue;

/**
 * SAPL 3.0.0 benchmark runner. Generates policies and runs JMH benchmarks
 * across all scenarios.
 * <p>
 * Usage: {@code java -jar sapl-benchmark3.jar <output-dir> [--large]}
 */
public class SaplBenchmark3 {

    public static void main(String[] args) throws Exception {
        if (args.length < 1 || args.length > 2) {
            System.err.println("Usage: SaplBenchmark3 <output-dir> [--large]");
            System.exit(1);
        }
        val outputDir  = Path.of(args[0]);
        val large      = args.length == 2 && "--large".equals(args[1]);
        val policyDir  = outputDir.resolve("policies");
        val resultsDir = outputDir.resolve("results");

        System.out.println("=== SAPL 3.0.0 Benchmark ===");
        System.out.println("Output: " + outputDir);
        System.out.println();

        System.out.println("Generating SAPL 3.0.0 policies...");
        PolicyGenerator.generate(policyDir, large);
        System.out.println();

        String[] scenarios;
        if (large) {
            scenarios = new String[] { "empty", "simple-1", "simple-10", "simple-100", "simple-500", "simple-1000",
                    "simple-5000", "simple-10000", "complex-1", "complex-10", "complex-100", "complex-1000",
                    "complex-5000", "complex-10000", "all-match-100", "all-match-1000" };
        } else {
            scenarios = new String[] { "empty", "simple-1", "simple-10", "simple-100", "simple-500", "complex-1",
                    "complex-10", "complex-100", "all-match-100" };
        }

        Files.createDirectories(resultsDir);

        for (val scenario : scenarios) {
            val scenarioDir = policyDir.resolve(scenario).toAbsolutePath().toString();
            val resultFile  = resultsDir.resolve(scenario + ".json").toString();

            System.out.println("=== " + scenario + " ===");

            val opts = new OptionsBuilder().include(EmbeddedBenchmark.class.getName()).forks(1)
                    .warmupIterations(2).warmupTime(TimeValue.seconds(2))
                    .measurementIterations(3).measurementTime(TimeValue.seconds(3))
                    .threads(1).param("policiesPath", scenarioDir)
                    .mode(Mode.Throughput).timeUnit(TimeUnit.SECONDS)
                    .shouldDoGC(true).syncIterations(true)
                    .resultFormat(ResultFormatType.JSON).result(resultFile).build();

            new Runner(opts).run();
            System.out.println();
        }

        System.out.println("=== Benchmark complete ===");
        System.out.println("Results in: " + resultsDir);
    }

}
