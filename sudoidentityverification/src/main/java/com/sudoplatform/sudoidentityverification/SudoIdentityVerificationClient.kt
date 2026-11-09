/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoidentityverification

import android.app.Activity
import android.content.Context
import android.os.Build
import androidx.annotation.RequiresApi
import com.sudoplatform.sudoapiclient.ApiClientManager
import com.sudoplatform.sudoidentityverification.types.DigitalCredentialVerificationOutcome
import com.sudoplatform.sudoidentityverification.types.IdentityDataProcessingConsentContent
import com.sudoplatform.sudoidentityverification.types.IdentityDataProcessingConsentStatus
import com.sudoplatform.sudoidentityverification.types.IdentityDocumentCaptureInitiationInfo
import com.sudoplatform.sudoidentityverification.types.VerifiedIdentity
import com.sudoplatform.sudoidentityverification.types.inputs.IdentityDataProcessingConsentContentInput
import com.sudoplatform.sudoidentityverification.types.inputs.IdentityDataProcessingConsentInput
import com.sudoplatform.sudoidentityverification.types.inputs.ResidentialAddressInput
import com.sudoplatform.sudoidentityverification.types.inputs.VerifyIdentityDocumentInput
import com.sudoplatform.sudoidentityverification.types.inputs.VerifyIdentityInput
import com.sudoplatform.sudologging.Logger
import com.sudoplatform.sudouser.SudoPlatformSignInCallback
import com.sudoplatform.sudouser.SudoUserClient
import com.sudoplatform.sudouser.amplify.GraphQLClient

/**
 * Interface encapsulating a library for interacting with the Sudo Platform Identity Verification service.
 */
interface SudoIdentityVerificationClient {
    companion object {
        /**
         * Creates a [Builder] for [SudoIdentityVerificationClient].
         */
        fun builder(
            context: Context,
            sudoUserClient: SudoUserClient,
        ) = Builder(context, sudoUserClient)
    }

    /**
     * Builder used to construct [SudoIdentityVerificationClient].
     */
    class Builder(
        private val context: Context,
        private val sudoUserClient: SudoUserClient,
    ) {
        private var graphQLClient: GraphQLClient? = null
        private var logger: Logger? = null

        /**
         * Provide a [GraphQLClient] for the [SudoIdentityVerificationClient]. If this is not
         * supplied, a [GraphQLClient] will be obtained from [ApiClientManager]. This is mainly
         * used for unit testing.
         */
        fun setGraphQLClient(graphQLClient: GraphQLClient) =
            also {
                this.graphQLClient = graphQLClient
            }

        /**
         * Provide the implementation of the [Logger] used for logging. If a value is not supplied
         * a default implementation will be used.
         */
        fun setLogger(logger: Logger) =
            also {
                this.logger = logger
            }

        /**
         * Constructs and returns an [SudoIdentityVerificationClient].
         */
        fun build(): SudoIdentityVerificationClient =
            DefaultSudoIdentityVerificationClient(
                this.context,
                this.sudoUserClient,
                this.logger ?: DefaultLogger.instance,
                this.graphQLClient ?: ApiClientManager.getClient(
                    this.context,
                    this.sudoUserClient,
                    "IdentityVerificationService",
                ),
            )
    }

    /**
     * Checksums for each file are generated and are used to create a checksum that is used when publishing to maven central.
     * In order to retry a failed publish without needing to change any functionality, we need a way to generate a different checksum
     * for the source code.  We can change the value of this property which will generate a different checksum for publishing
     * and allow us to retry.  The value of `version` doesn't need to be kept up-to-date with the version of the code.
     */
    val version: String

    /**
     * Sets an optional callback to be invoked when operations are attempted while not signed in.
     * When set, all operations (except subscriptions and initialization) will check sign-in status
     * and invoke this callback if the user is not signed in.
     * Setting the callback to null disables automatic sign-in checking, restoring the default
     * behavior where operations proceed without sign-in checks.
     * If the callback throws an exception, that exception is propagated
     * to the caller and the original operation is not executed.
     *
     * @param callback An optional [SudoPlatformSignInCallback] to handle sign-in. Pass null to disable
     *                 automatic sign-in checking. The callback may throw exceptions which
     *                 will be propagated to the caller.
     */
    fun setSignInCallback(callback: SudoPlatformSignInCallback?)

    /**
     * Retrieves the list of supported countries for identity verification.
     *
     * @return a list of supported countries.
     *
     * @throws [SudoIdentityVerificationException].
     */
    @Throws(SudoIdentityVerificationException::class)
    suspend fun listSupportedCountries(): List<String>

    /**
     * Flag indicating if face image must be submitted as part of identity
     * document capture.
     *
     * @return boolean flag.
     *
     * @throws [SudoIdentityVerificationException].
     */
    @Throws(SudoIdentityVerificationException::class)
    suspend fun isFaceImageRequiredWithDocumentCapture(): Boolean

    /**
     * Flag indicating if face image must be submitted as part of identity
     * document verification.
     *
     * @return boolean flag.
     *
     * @throws [SudoIdentityVerificationException].
     */
    @Throws(SudoIdentityVerificationException::class)
    suspend fun isFaceImageRequiredWithDocumentVerification(): Boolean

    /**
     * Retrieves the flag for whether document capture can be initiated using
     * initiateIdentityDocumentCapture().
     *
     * @return boolean flag.
     *
     * @throws [SudoIdentityVerificationException].
     */
    @Throws(SudoIdentityVerificationException::class)
    suspend fun isDocumentCaptureInitiationEnabled(): Boolean

    /**
     * Flag indicating if consent is required to perform identity data processing.
     *
     * @return boolean flag.
     *
     * @throws [SudoIdentityVerificationException].
     */
    @Throws(SudoIdentityVerificationException::class)
    suspend fun isConsentRequiredForVerification(): Boolean

    /**
     * Flag indicating if the service accepts identity verification with a digital credential
     * using [verifyIdentityWithDigitalCredential]. This reflects the service configuration only;
     * it does not indicate whether the device or any wallet on it can present a credential.
     *
     * @return boolean flag.
     *
     * @throws [SudoIdentityVerificationException].
     */
    @Throws(SudoIdentityVerificationException::class)
    suspend fun isDigitalCredentialVerificationEnabled(): Boolean

    /**
     * Checks the identity verification status of the currently signed in user.
     *
     * @returns A [VerifiedIdentity] verification result.
     *
     * @throws [SudoIdentityVerificationException].
     */
    @Throws(SudoIdentityVerificationException::class)
    suspend fun checkIdentityVerification(): VerifiedIdentity

    /**
     * Verifies an identity against the known public records and returns a result indicating whether
     * or not the identity details provided was verified with enough confidence to grant the user
     * access to Sudo Platform functions such as provisioning a virtual card.
     *
     * @param input [VerifyIdentityInput] Parameters consisting of personally identifiable
     *  information required to verify an identity.
     * @return A [VerifiedIdentity] verification result.
     *
     * @throws [SudoIdentityVerificationException].
     */
    @Throws(SudoIdentityVerificationException::class)
    suspend fun verifyIdentity(input: VerifyIdentityInput): VerifiedIdentity

    /**
     * Attempts to verify an identity based on provided identity documents.
     *
     * @param input [VerifyIdentityDocumentInput] Parameters used to verify an identity using
     *  provided identity documents.
     * @return A [VerifiedIdentity] verification result.
     *
     * @throws [SudoIdentityVerificationException].
     */
    @Throws(SudoIdentityVerificationException::class)
    suspend fun verifyIdentityDocument(input: VerifyIdentityDocumentInput): VerifiedIdentity

    /**
     * Attempts to capture an identity document and verify identity using the information in
     * the provided identity documents.
     *
     * @param input [VerifyIdentityDocumentInput] Parameters used to verify an identity using
     *  provided identity documents.
     * @return A [VerifiedIdentity] verification result.
     *
     * @throws [SudoIdentityVerificationException].
     */
    @Throws(SudoIdentityVerificationException::class)
    suspend fun captureAndVerifyIdentityDocument(input: VerifyIdentityDocumentInput): VerifiedIdentity

    /**
     * Verifies identity using a digital credential, such as a mobile driver's licence, held in a
     * wallet on the device. Requests a presentation from the service, shows the Credential Manager
     * credential selector so the user can choose a credential, then submits the presentation to
     * the service for verification.
     *
     * A successful verification completes identity verification on its own; the knowledge of PII
     * step performed by [verifyIdentity] is not required.
     *
     * Where the service requires a residential address and the presented credential carries
     * none, such as a Google ID pass, the result is
     * [DigitalCredentialVerificationOutcome.ResidentialAddressRequired]. Collect the user's
     * address and pass the result to [completeDigitalCredentialVerification].
     *
     * The service only accepts presentations from apps whose signing certificate is in its list
     * of permitted origins.
     *
     * @param activity [Activity] The activity the credential selector is shown over.
     * @return A [DigitalCredentialVerificationOutcome] verification outcome.
     *
     * @throws [SudoIdentityVerificationException.DigitalCredentialCancelledException] if the user
     *  dismissed the credential selector.
     * @throws [SudoIdentityVerificationException.NoDigitalCredentialException] if no credential
     *  on the device satisfies the request.
     * @throws [SudoIdentityVerificationException.DigitalCredentialUnsupportedException] if the
     *  device cannot request digital credentials.
     * @throws [SudoIdentityVerificationException.DigitalCredentialRequestExpiredException] if the
     *  request expired before a credential was presented.
     * @throws [SudoIdentityVerificationException.DigitalCredentialVerificationFailedException] if
     *  the presented credential was rejected as malformed or not authentic.
     * @throws [SudoIdentityVerificationException.DigitalCredentialIssuerNotTrustedException] if
     *  the presented credential's issuer is not trusted.
     * @throws [SudoIdentityVerificationException.DigitalCredentialNotAcceptedException] if the
     *  presented credential is not of an accepted type.
     * @throws [SudoIdentityVerificationException.DigitalCredentialNoLongerValidException] if the
     *  presented credential, or the certificate that signed it, has expired or been revoked.
     * @throws [SudoIdentityVerificationException].
     */
    @RequiresApi(Build.VERSION_CODES.P)
    @Throws(SudoIdentityVerificationException::class)
    suspend fun verifyIdentityWithDigitalCredential(activity: Activity): DigitalCredentialVerificationOutcome

    /**
     * Completes a digital credential verification that requires the user's residential address,
     * by submitting the presentation again with the address. The user does not present a
     * credential again.
     *
     * The service verifies the address against the identity verification provider's records,
     * using the name and date of birth from the credential.
     *
     * @param pending [DigitalCredentialVerificationOutcome.ResidentialAddressRequired] The
     *  outcome of [verifyIdentityWithDigitalCredential] to complete.
     * @param address [ResidentialAddressInput] The user's residential address.
     * @return A [VerifiedIdentity] verification result, which is unverified if the address was
     *  not verified.
     *
     * @throws [SudoIdentityVerificationException.DigitalCredentialRequestExpiredException] if the
     *  presentation can no longer be completed; start a new verification.
     * @throws [SudoIdentityVerificationException.UnsupportedCountryException] if the address is
     *  not in a supported country; it may be corrected and submitted again.
     * @throws [SudoIdentityVerificationException.RequiredIdentityInformationNotProvidedException]
     *  if the presentation was submitted without an address too many times; start a new
     *  verification.
     * @throws [SudoIdentityVerificationException].
     */
    @Throws(SudoIdentityVerificationException::class)
    suspend fun completeDigitalCredentialVerification(
        pending: DigitalCredentialVerificationOutcome.ResidentialAddressRequired,
        address: ResidentialAddressInput,
    ): VerifiedIdentity

    /**
     * Attempts to initiate ID document capture using underlying provider's web based method.
     *
     * @return A [IdentityDocumentCaptureInitiationInfo] verification result.
     *
     * @throws [SudoIdentityVerificationException].
     */
    @Throws(SudoIdentityVerificationException::class)
    suspend fun initiateIdentityDocumentCapture(): IdentityDocumentCaptureInitiationInfo

    /**
     * Provides consent for identity data processing.
     *
     * @param input [IdentityDataProcessingConsentInput] Parameters for consent content.
     * @return [Boolean] result.
     *
     * @throws [SudoIdentityVerificationException].
     */
    @Throws(SudoIdentityVerificationException::class)
    suspend fun provideIdentityDataProcessingConsent(input: IdentityDataProcessingConsentInput): Boolean

    /**
     * Withdraws consent for identity data processing.
     *
     * @return [Boolean] result.
     *
     * @throws [SudoIdentityVerificationException].
     */
    @Throws(SudoIdentityVerificationException::class)
    suspend fun withdrawIdentityDataProcessingConsent(): Boolean

    /**
     * Retrieves the content for identity data processing consent,
     *  given the provided preferred content type and language (in RFC 5646 format).
     *
     * @param input [IdentityDataProcessingConsentContentInput] Parameters for content retrieval.
     * @return [IdentityDataProcessingConsentContent] result.
     *
     * @throws [SudoIdentityVerificationException].
     */
    @Throws(SudoIdentityVerificationException::class)
    suspend fun getIdentityDataProcessingConsentContent(
        input: IdentityDataProcessingConsentContentInput,
    ): IdentityDataProcessingConsentContent

    /**
     * Retrieves the status of identity data processing consent.
     *
     * @return [IdentityDataProcessingConsentStatus] result.
     *
     * @throws [SudoIdentityVerificationException].
     */
    @Throws(SudoIdentityVerificationException::class)
    suspend fun getIdentityDataProcessingConsentStatus(): IdentityDataProcessingConsentStatus

    /**
     * Reset any internal state and cached content.
     */
    fun reset()
}
