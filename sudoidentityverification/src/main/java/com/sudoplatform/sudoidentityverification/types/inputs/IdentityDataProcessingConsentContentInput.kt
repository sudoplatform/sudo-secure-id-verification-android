/*
 * Copyright © 2025 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoidentityverification.types.inputs

/**
 * Input for retrieving identity data processing consent content.
 */
data class IdentityDataProcessingConsentContentInput(
    val preferredContentType: String,
    val preferredLanguage: String,
)
