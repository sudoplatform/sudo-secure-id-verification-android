/*
 * Copyright © 2024 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoidentityverification.types

/**
 * Verification method used for identity verification.
 */
enum class VerificationMethod(
    val type: String,
) {
    NONE("NONE"),
    KNOWLEDGE_OF_PII("KNOWLEDGE_OF_PII"),
    GOVERNMENT_ID("GOVERNMENT_ID"),
    UNKNOWN("UNKNOWN"),
}
