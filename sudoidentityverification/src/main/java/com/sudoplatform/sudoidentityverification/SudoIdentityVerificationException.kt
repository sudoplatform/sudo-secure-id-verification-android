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
sealed class SudoIdentityVerificationException(
    message: String? = null,
    cause: Throwable? = null,
) : RuntimeException(message, cause) {
    /**
     * The Verified Identity cannot be found.
     * The Verified Identity attempted to be accessed does not exist or cannot be found.
     */
    class IdentityVerificationRecordNotFoundException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoIdentityVerificationException(message = message, cause = cause)

    /**
     * An attempt to update the Verified Identity has failed.
     */
    class IdentityVerificationUpdateFailedException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoIdentityVerificationException(message = message, cause = cause)

    /**
     * The method used for verification is unsupported.
     */
    class UnsupportedVerificationMethodException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoIdentityVerificationException(message = message, cause = cause)

    /**
     * An implausible age was input for verification.
     */
    class ImplausibleAgeException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoIdentityVerificationException(message = message, cause = cause)

    /**
     * An invalid age was input for verification.
     */
    class InvalidAgeException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoIdentityVerificationException(message = message, cause = cause)

    /**
     * An unsupported country was associated with an identity to be verified.
     */
    class UnsupportedCountryException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoIdentityVerificationException(message = message, cause = cause)

    /**
     * An identity verification attempt was initiated with insufficient information.
     */
    class RequiredIdentityInformationNotProvidedException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoIdentityVerificationException(message = message, cause = cause)

    /**
     * An identity verification attempt originated from an unsupported network location.
     */
    class UnsupportedNetworkLocationException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoIdentityVerificationException(message = message, cause = cause)

    /**
     * An operation for unverified user was invoked for a user for which identity verification was
     * already completed.
     */
    class IdentityAlreadyVerifiedException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoIdentityVerificationException(message = message, cause = cause)

    /**
     * Identity document capture attempts has been exceeded.
     */
    class IdentityCaptureRetriesExceededException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoIdentityVerificationException(message = message, cause = cause)

    /**
     * Identity document capture additional attempts has been prevented.
     */
    class IdentityCaptureRetryBlockedException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoIdentityVerificationException(message = message, cause = cause)

    /**
     * Identity data retrieval attempted for a user whose data has been redacted due to
     * policy or is no longer available.
     */
    class IdentityDataRedactedException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoIdentityVerificationException(message = message, cause = cause)

    /**
     * Indicates the user is not signed in but requested an operation that requires authentication.
     */
    class NotSignedInException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoIdentityVerificationException(message = message, cause = cause)

    /**
     * An identity data processing operation was called in an environment which requires consent,
     * and consent had not been provided.
     */
    class ConsentRequiredException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoIdentityVerificationException(message = message, cause = cause)

    /**
     * The user dismissed the digital credential selection without presenting a credential.
     */
    class DigitalCredentialCancelledException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoIdentityVerificationException(message = message, cause = cause)

    /**
     * No wallet on the device holds a digital credential that satisfies the request.
     */
    class NoDigitalCredentialException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoIdentityVerificationException(message = message, cause = cause)

    /**
     * Credential Manager on this device cannot request digital credentials, for example because
     * the device does not support it or Google Play services is unavailable or out of date.
     */
    class DigitalCredentialUnsupportedException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoIdentityVerificationException(message = message, cause = cause)

    /**
     * The digital credential request issued by the service expired before a credential was
     * presented. A new verification attempt can be started.
     */
    class DigitalCredentialRequestExpiredException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoIdentityVerificationException(message = message, cause = cause)

    /**
     * The presented digital credential was rejected because the wallet response is malformed,
     * not bound to the request it was presented for, or not authentic. A new verification
     * attempt can be started.
     */
    class DigitalCredentialVerificationFailedException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoIdentityVerificationException(message = message, cause = cause)

    /**
     * The presented digital credential was issued by an authority the service does not trust.
     * The credential may be genuine; a credential from a different issuer or wallet may be
     * accepted.
     */
    class DigitalCredentialIssuerNotTrustedException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoIdentityVerificationException(message = message, cause = cause)

    /**
     * The presented digital credential is not of a type the service accepts, such as an identity
     * pass where only a driving licence is accepted.
     */
    class DigitalCredentialNotAcceptedException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoIdentityVerificationException(message = message, cause = cause)

    /**
     * The presented digital credential is no longer valid: it has expired, or the certificate
     * its issuer signed it with has expired or been revoked. The user may be able to refresh
     * the credential in their wallet.
     */
    class DigitalCredentialNoLongerValidException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoIdentityVerificationException(message = message, cause = cause)

    /**
     * Internal server error occurred in Identity Verification service.
     */
    class InternalServerException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoIdentityVerificationException(message = message, cause = cause)

    /**
     * Unexpected error occurred during API invocation.
     */
    class FailedException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoIdentityVerificationException(message = message, cause = cause)

    /**
     * Indicates the user is not authenticated in order to perform the request.
     */
    class AuthenticationException(
        message: String? = null,
        cause: Throwable? = null,
    ) : SudoIdentityVerificationException(message = message, cause = cause)

    /**
     * A catch all error for any unknown or unhandled exceptions.
     */
    class UnknownException(
        cause: Throwable,
    ) : SudoIdentityVerificationException(cause = cause)
}
