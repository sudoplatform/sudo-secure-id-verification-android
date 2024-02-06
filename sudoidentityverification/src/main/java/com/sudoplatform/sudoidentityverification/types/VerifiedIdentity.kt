/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoidentityverification.types

import java.util.Date

/**
 * Represents a verified identity resulting from calling [SudoIdentityVerificationClient.verifyIdentity] API.
 *
 * @property owner [String] User ID of the user who provided identity details for verification.
 * @property verified [Boolean] `true` if the identity was verified successfully.
 * @property verifiedAt [Date] Date and time at which the identity was verified.
 * @property verificationMethod [VerificationMethod] Verification method used.
 * @property canAttemptVerificationAgain [Boolean] Indicates whether or not identity verification
 *  can be attempted again for this user. Set to false in cases where the maximum number of attempts
 *  has been reached or a finding from the identity verification attempt means that it should not
 *  proceed.
 * @property idScanUrl [String] URL to upload the scanned documents for identity verification.
 */
data class VerifiedIdentity(
    val owner: String,
    val verified: Boolean,
    val verifiedAt: Date?,
    val verificationMethod: VerificationMethod,
    val canAttemptVerificationAgain: Boolean,
    val idScanUrl: String?,
    val requiredVerificationMethod: VerificationMethod?,
    val acceptableDocumentTypes: List<IdDocumentType>,
    val documentVerificationStatus: DocumentVerificationStatus,
)
