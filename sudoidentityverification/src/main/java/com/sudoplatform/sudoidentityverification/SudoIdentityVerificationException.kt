/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoidentityverification

/**
 * Defines the exceptions thrown by method of the [SudoIdentityVerificationClient].
 *
 * @property message [String] Accompanying message for the exception.
 * @property cause [Throwable] The cause for the exception.
 */
sealed class SudoIdentityVerificationException(message: String? = null, cause: Throwable? = null) : RuntimeException(message, cause) {
    /**
     * The Verified Identity cannot be found.
     * The Verified Identity attempted to be accessed does not exist or cannot be found.
     */
    class IdentityVerificationRecordNotFoundException(message: String? = null, cause: Throwable? = null) :
        SudoIdentityVerificationException(message = message, cause = cause)

    /**
     * An attempt to update the Verified Identity has failed.
     */
    class IdentityVerificationUpdateFailedException(message: String? = null, cause: Throwable? = null) :
        SudoIdentityVerificationException(message = message, cause = cause)

    /**
     * The method used for verification is unsupported.
     */
    class UnsupportedVerificationMethodException(message: String? = null, cause: Throwable? = null) :
        SudoIdentityVerificationException(message = message, cause = cause)

    /**
     * An implausible age was input for verification.
     */
    class ImplausibleAgeException(message: String? = null, cause: Throwable? = null) :
        SudoIdentityVerificationException(message = message, cause = cause)

    /**
     * An invalid age was input for verification.
     */
    class InvalidAgeException(message: String? = null, cause: Throwable? = null) :
        SudoIdentityVerificationException(message = message, cause = cause)

    /**
     * An unsupported country was associated with an identity to be verified.
     */
    class UnsupportedCountryException(message: String? = null, cause: Throwable? = null) :
        SudoIdentityVerificationException(message = message, cause = cause)

    /**
     * An identity verification attempt originated from an unsupported network location.
     */
    class UnsupportedNetworkLocationException(message: String? = null, cause: Throwable? = null) :
        SudoIdentityVerificationException(message = message, cause = cause)

    /**
     * Indicates the user is not signed in but requested an operation that requires authentication.
     */
    class NotSignedInException(message: String? = null, cause: Throwable? = null) :
        SudoIdentityVerificationException(message = message, cause = cause)

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
     * Indicates the user is not authenticated in order to perform the request.
     */
    class AuthenticationException(message: String? = null, cause: Throwable? = null) :
        SudoIdentityVerificationException(message = message, cause = cause)

    /**
     * A catch all error for any unknown or unhandled exceptions.
     */
    class UnknownException(cause: Throwable) :
        SudoIdentityVerificationException(cause = cause)
}
