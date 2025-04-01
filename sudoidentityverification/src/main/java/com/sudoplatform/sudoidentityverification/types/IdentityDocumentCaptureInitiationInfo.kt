/*
 * Copyright © 2025 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoidentityverification.types

import java.util.Date

/**
 * Represents identity document capture initiation details obtained via [initiateIdentityDocumentCapture] API.
 *
 * @property documentCaptureUrl [String] URL for uploading identity document information.
 * @property expiryAt [Date] When the document capture URL is no longer usable.
 */
data class IdentityDocumentCaptureInitiationInfo(
    val documentCaptureUrl: String,
    val expiryAt: Date,
)
