/*
 * Copyright (C) 2017-2026 Dominic Heutelbeck (dominic@heutelbeck.com)
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package io.sapl.benchmark3;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Generates SAPL 3.0.0 benchmark policies. Uses the {@code where} keyword
 * and the flat combining algorithm enum format in pdp.json.
 */
class PolicyGenerator {

    private static final String PDP_JSON = """
            {
              "algorithm": "DENY_OVERRIDES",
              "variables": {}
            }
            """;

    private static final String MATCHING_SIMPLE = """
            policy "matching-policy"
            permit action == "read"
            where
                resource == "document";
            """;

    private static final String NON_MATCHING_SIMPLE = """
            policy "filler-%04d"
            permit action == "action-%04d"
            where
                resource == "resource-%04d";
            """;

    private static final String MATCHING_COMPLEX = """
            policy "matching-complex"
            permit action == "read"
            where
                resource == "document";
                "admin" in subject.roles;
                subject.department =~ "^engineering.*";
                var level = subject.clearanceLevel;
            obligation
                {
                    "type"    : "logAccess",
                    "message" : subject.name + " accessed " + resource + " at level " + level
                }
            advice
                {
                    "type"    : "audit",
                    "details" : "read access to " + resource + " by " + subject.name
                }
            """;

    private static final String NON_MATCHING_COMPLEX = """
            policy "filler-complex-%04d"
            permit action == "action-%04d"
            where
                resource == "resource-%04d";
                "role-%04d" in subject.roles;
                subject.department =~ "^department-%04d.*";
                var ref = subject.clearanceLevel;
            obligation
                {
                    "type"    : "logAccess",
                    "message" : subject.name + " accessed resource-%04d at level " + ref
                }
            advice
                {
                    "type"    : "audit",
                    "details" : "access to resource-%04d by " + subject.name
                }
            """;

    private static final String ALL_MATCHING_SIMPLE = """
            policy "match-all-%04d"
            permit action == "read"
            where
                resource == "document";
            """;

    static void generate(Path outputDir, boolean large) throws IOException {
        Files.createDirectories(outputDir);

        generateEmpty(outputDir.resolve("empty"));
        generateSimple(outputDir.resolve("simple-1"), 1);
        generateSimple(outputDir.resolve("simple-10"), 10);
        generateSimple(outputDir.resolve("simple-100"), 100);
        generateSimple(outputDir.resolve("simple-500"), 500);

        generateComplex(outputDir.resolve("complex-1"), 1);
        generateComplex(outputDir.resolve("complex-10"), 10);
        generateComplex(outputDir.resolve("complex-100"), 100);

        generateAllMatch(outputDir.resolve("all-match-100"), 100);

        generateRbacOpa(outputDir.resolve("rbac-small"));
        generateRbacExplosion(outputDir.resolve("rbac-large"));

        if (large) {
            generateSimple(outputDir.resolve("simple-1000"), 1000);
            generateSimple(outputDir.resolve("simple-5000"), 5000);
            generateSimple(outputDir.resolve("simple-10000"), 10000);
            generateComplex(outputDir.resolve("complex-1000"), 1000);
            generateComplex(outputDir.resolve("complex-5000"), 5000);
            generateComplex(outputDir.resolve("complex-10000"), 10000);
            generateAllMatch(outputDir.resolve("all-match-1000"), 1000);
        }
    }

    private static void generateEmpty(Path dir) throws IOException {
        Files.createDirectories(dir);
        Files.writeString(dir.resolve("pdp.json"), PDP_JSON);
    }

    private static void generateSimple(Path dir, int count) throws IOException {
        Files.createDirectories(dir);
        Files.writeString(dir.resolve("pdp.json"), PDP_JSON);
        Files.writeString(dir.resolve("matching.sapl"), MATCHING_SIMPLE);
        for (var i = 2; i <= count; i++) {
            Files.writeString(dir.resolve("filler-%04d.sapl".formatted(i)), NON_MATCHING_SIMPLE.formatted(i, i, i));
        }
    }

    private static void generateComplex(Path dir, int count) throws IOException {
        Files.createDirectories(dir);
        Files.writeString(dir.resolve("pdp.json"), PDP_JSON);
        Files.writeString(dir.resolve("matching.sapl"), MATCHING_COMPLEX);
        for (var i = 2; i <= count; i++) {
            Files.writeString(dir.resolve("filler-%04d.sapl".formatted(i)),
                    NON_MATCHING_COMPLEX.formatted(i, i, i, i, i, i, i));
        }
    }

    private static void generateAllMatch(Path dir, int count) throws IOException {
        Files.createDirectories(dir);
        Files.writeString(dir.resolve("pdp.json"), PDP_JSON);
        for (var i = 1; i <= count; i++) {
            Files.writeString(dir.resolve("match-%04d.sapl".formatted(i)), ALL_MATCHING_SIMPLE.formatted(i));
        }
    }

    private static void generateRbacOpa(Path dir) throws IOException {
        Files.createDirectories(dir);
        var pdpJson = """
                {
                  "algorithm": "DENY_OVERRIDES",
                  "variables": {
                    "permissions" : {
                      "dev" : [
                          { "type": "foo123", "action": "write" },
                          { "type": "foo123", "action": "read"  }
                        ],
                      "test" : [
                          { "type": "foo123", "action": "read" }
                        ]
                    }
                  }
                }
                """;
        var policy = """
                policy "RBAC"
                permit
                where
                    { "type" : resource.type, "action": action } in permissions[(subject.role)];
                """;
        Files.writeString(dir.resolve("pdp.json"), pdpJson);
        Files.writeString(dir.resolve("rbac.sapl"), policy);
    }

    private static final String[] DEPARTMENTS = { "engineering", "qa", "sales", "marketing", "finance", "hr", "ops",
            "legal", "security", "support" };
    private static final String[] LOCATIONS   = { "london", "berlin", "new-york", "singapore", "sydney" };
    private static final String[] SENIORITIES = { "junior", "senior", "lead", "director" };
    private static final String[] ACTIONS     = { "read", "write", "delete", "approve" };

    private static void generateRbacExplosion(Path dir) throws IOException {
        Files.createDirectories(dir);
        var permissions = new StringBuilder("{\n");
        var first       = true;
        for (var dept : DEPARTMENTS) {
            for (var loc : LOCATIONS) {
                for (var seniority : SENIORITIES) {
                    var roleName = dept + "-" + loc + "-" + seniority;
                    if (!first) {
                        permissions.append(",\n");
                    }
                    first = false;
                    permissions.append("        \"%s\" : [\n".formatted(roleName));
                    var perms    = new java.util.ArrayList<String>();
                    var maxAction = switch (seniority) {
                        case "junior"   -> 1;
                        case "senior"   -> 2;
                        case "lead"     -> 3;
                        case "director" -> 4;
                        default         -> 1;
                    };
                    for (var a = 0; a < maxAction; a++) {
                        perms.add("            { \"type\": \"%s-%s\", \"action\": \"%s\" }".formatted(dept, loc, ACTIONS[a]));
                    }
                    permissions.append(String.join(",\n", perms));
                    permissions.append("\n          ]");
                }
            }
        }
        permissions.append("\n      }");

        var pdpJson = """
                {
                  "algorithm": "DENY_OVERRIDES",
                  "variables": {
                    "permissions" : %s
                  }
                }
                """.formatted(permissions);

        var policy = """
                policy "RBAC"
                permit
                where
                    { "type" : resource.type, "action": action } in permissions[(subject.role)];
                """;

        Files.writeString(dir.resolve("pdp.json"), pdpJson);
        Files.writeString(dir.resolve("rbac.sapl"), policy);
    }

}
