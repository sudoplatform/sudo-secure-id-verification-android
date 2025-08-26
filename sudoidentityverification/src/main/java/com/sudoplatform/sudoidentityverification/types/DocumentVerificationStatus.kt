/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoidentityverification.types

/**
 * Status of document verification process for an identity
 */
enum class DocumentVerificationStatus(
    val type: String,
) {
    NOT_REQUIRED("notRequired"),
    NOT_ATTEMPTED("notAttempted"),
    PENDING("pending"),
    DOCUMENT_UNREADABLE("documentUnreadable"),
    FAILED("failed"),
    SUCCEEDED("succeeded"),
    UNKNOWN("Unknown"),
}
