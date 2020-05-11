/**
 * Copyright © 2020 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoidentityverification

import java.util.*

/**
 * Represents a verified identity resulting from calling [SudoIdentityVerificationClient.verifyIdentity] API.
 */
data class VerifiedIdentity(

    /**
     * User ID of the user who provided identity details for verification.
     */
    val owner: String,

    /**
     * `true` if the identity was verified successfully.
     */
    val verified: Boolean,

    /**
     * Date and time at which the identity was verified.
     */
    val verifiedAt: Date?,

    /**
     * Verification method used.
     */
    val verificationMethod: String,

    /**
     * Indicates whether or not identity verification can be attempted again for this user. Set to
     * false in cases where the maximum number of attempts has been reached or a finding from the
     * identity verification attempt means that it should not proceed.
     */
    val canAttemptVerificationAgain: Boolean,

    /**
     * URL to upload the scanned documents for identity verification.
     */
    val idScanUrl: String?

)
