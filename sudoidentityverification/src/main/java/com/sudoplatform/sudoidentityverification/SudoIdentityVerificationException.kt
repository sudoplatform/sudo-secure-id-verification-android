/**
 * Copyright © 2020 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoidentityverification

sealed class SudoIdentityVerificationException(message: String? = null, cause: Throwable? = null) :  RuntimeException(message, cause) {
    /**
     * Internal server error occurred in Identity Verification service.
     */
    class InternalServerException(message: String? = null, cause: Throwable? = null) :
        SudoIdentityVerificationException(message = message, cause = cause)

    /**
     * Unexpected error occurred during API invocation.
     */
    class FailedException(message: String? = null, cause: Throwable? = null) :
        SudoIdentityVerificationException(message = message, cause = cause)

}
