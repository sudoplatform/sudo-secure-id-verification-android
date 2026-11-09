/*
 * Copyright © 2026 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoidentityverification.types

import java.time.Instant

/**
 * The outcome of presenting a digital credential for identity verification.
 */
sealed interface DigitalCredentialVerificationOutcome {
    /**
     * The presentation was processed.
     *
     * @property verifiedIdentity [VerifiedIdentity] The verification result, which may be
     *  unverified.
     */
    data class Completed(
        val verifiedIdentity: VerifiedIdentity,
    ) : DigitalCredentialVerificationOutcome

    /**
     * The presented credential carries no residential address and one is required. Collect the
     * holder's address and pass this to
     * [SudoIdentityVerificationClient.completeDigitalCredentialVerification] before [expiresAt].
     *
     * @property expiresAt [Instant] When the presentation can no longer be completed. After that,
     *  the holder must present a credential again.
     */
    class ResidentialAddressRequired internal constructor(
        internal val response: String,
        val expiresAt: Instant,
    ) : DigitalCredentialVerificationOutcome
}
