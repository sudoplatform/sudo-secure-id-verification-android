/*
 * Copyright © 2025 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoidentityverification.types

/**
 * Content for identity data processing consent.
 * Matches GraphQL: type IdentityDataProcessingConsentContent
 */
data class IdentityDataProcessingConsentContent(
    val content: String,
    val contentType: String,
    val locale: String,
)
