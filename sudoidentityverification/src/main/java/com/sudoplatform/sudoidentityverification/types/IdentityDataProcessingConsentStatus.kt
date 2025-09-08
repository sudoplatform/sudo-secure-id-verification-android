/*
 * Copyright © 2025 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoidentityverification.types

/**
 * Status of identity data processing consent.
 * Matches GraphQL: type IdentityDataProcessingConsentStatus
 */
data class IdentityDataProcessingConsentStatus(
    val consented: Boolean,
    val consentedAtEpochMs: Double?,
    val consentWithdrawnAtEpochMs: Double?,
    val content: String?,
    val contentType: String?,
    val language: String?,
)
