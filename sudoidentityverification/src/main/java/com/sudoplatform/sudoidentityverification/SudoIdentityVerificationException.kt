/**
 * Copyright © 2020 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoidentityverification

import com.sudoplatform.sudouser.exceptions.AuthenticationException

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

    /**
     * Indicates the user is not signed in but requested an operation that requires authentication.
     */
    class NotSignedInException(message: String? = null, cause: Throwable? = null) :
        SudoIdentityVerificationException(message = message, cause = cause)

}
