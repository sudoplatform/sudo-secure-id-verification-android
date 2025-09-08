/*
 * Copyright © 2025 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoidentityverification.types.inputs

/**
 * Input for providing identity data processing consent.
 * Matches GraphQL: input IdentityDataProcessingConsentInput
 */
data class IdentityDataProcessingConsentInput(
    val content: String,
    val contentType: String,
    val language: String,
)
