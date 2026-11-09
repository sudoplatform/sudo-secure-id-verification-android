/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoidentityverification

import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.credentials.CredentialManager
import androidx.credentials.DigitalCredential
import androidx.credentials.ExperimentalDigitalCredentialApi
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetDigitalCredentialOption
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialProviderConfigurationException
import androidx.credentials.exceptions.GetCredentialUnsupportedException
import androidx.credentials.exceptions.NoCredentialException
import com.amazonaws.services.cognitoidentity.model.NotAuthorizedException
import com.amplifyframework.api.graphql.GraphQLResponse
import com.apollographql.apollo.api.Optional
import com.sudoplatform.sudoapiclient.ApiClientManager
import com.sudoplatform.sudoidentityverification.graphql.CaptureAndVerifyIdentityDocumentMutation
import com.sudoplatform.sudoidentityverification.graphql.CheckIdentityVerificationQuery
import com.sudoplatform.sudoidentityverification.graphql.FinalizeDigitalCredentialVerificationMutation
import com.sudoplatform.sudoidentityverification.graphql.GetIdentityDataProcessingConsentContentQuery
import com.sudoplatform.sudoidentityverification.graphql.GetIdentityDataProcessingConsentStatusQuery
import com.sudoplatform.sudoidentityverification.graphql.GetIdentityVerificationCapabilitiesQuery
import com.sudoplatform.sudoidentityverification.graphql.InitiateDigitalCredentialVerificationMutation
import com.sudoplatform.sudoidentityverification.graphql.InitiateIdentityDocumentCaptureMutation
import com.sudoplatform.sudoidentityverification.graphql.ProvideIdentityDataProcessingConsentMutation
import com.sudoplatform.sudoidentityverification.graphql.VerifyIdentityDocumentMutation
import com.sudoplatform.sudoidentityverification.graphql.VerifyIdentityMutation
import com.sudoplatform.sudoidentityverification.graphql.WithdrawIdentityDataProcessingConsentMutation
import com.sudoplatform.sudoidentityverification.graphql.type.DigitalCredentialFlow
import com.sudoplatform.sudoidentityverification.graphql.type.DigitalCredentialResidentialAddressInput
import com.sudoplatform.sudoidentityverification.graphql.type.FinalizeDigitalCredentialVerificationInput
import com.sudoplatform.sudoidentityverification.graphql.type.InitiateDigitalCredentialVerificationInput
import com.sudoplatform.sudoidentityverification.types.DigitalCredentialVerificationOutcome
import com.sudoplatform.sudoidentityverification.types.IdentityDataProcessingConsentContent
import com.sudoplatform.sudoidentityverification.types.IdentityDataProcessingConsentStatus
import com.sudoplatform.sudoidentityverification.types.IdentityDocumentCaptureInitiationInfo
import com.sudoplatform.sudoidentityverification.types.IdentityDocumentCaptureInitiationInfoTransformer
import com.sudoplatform.sudoidentityverification.types.VerifiedIdentity
import com.sudoplatform.sudoidentityverification.types.VerifiedIdentityTransformer
import com.sudoplatform.sudoidentityverification.types.inputs.IdentityDataProcessingConsentContentInput
import com.sudoplatform.sudoidentityverification.types.inputs.IdentityDataProcessingConsentInput
import com.sudoplatform.sudoidentityverification.types.inputs.ResidentialAddressInput
import com.sudoplatform.sudoidentityverification.types.inputs.VerifyIdentityDocumentInput
import com.sudoplatform.sudoidentityverification.types.inputs.VerifyIdentityInput
import com.sudoplatform.sudologging.Logger
import com.sudoplatform.sudouser.SignInGuard
import com.sudoplatform.sudouser.SudoPlatformSignInCallback
import com.sudoplatform.sudouser.SudoUserClient
import com.sudoplatform.sudouser.amplify.GraphQLClient
import com.sudoplatform.sudouser.exceptions.GRAPHQL_ERROR_TYPE
import com.sudoplatform.sudouser.exceptions.HTTP_STATUS_CODE_KEY
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.net.HttpURLConnection
import java.security.MessageDigest
import java.time.Instant
import java.util.Base64
import java.util.concurrent.CancellationException
import com.sudoplatform.sudoidentityverification.graphql.type.IdentityDataProcessingConsentContentInput as GraphQLIdentityDataProcessingConsentContentInput
import com.sudoplatform.sudoidentityverification.graphql.type.IdentityDataProcessingConsentInput as GraphQLIdentityDataProcessingConsentInput
import com.sudoplatform.sudoidentityverification.graphql.type.VerifyIdentityDocumentInput as VerifyIdentityDocumentMutationInput
import com.sudoplatform.sudoidentityverification.graphql.type.VerifyIdentityInput as VerifyIdentityMutationInput

/**
 * Default implementation of the [SudoIdentityVerificationClient] interface.
 *
 * @property context [Context] Application context.
 * @property sudoUserClient [SudoUserClient] Instance required to issue authentication tokens and perform
 *  cryptographic operations.
 * @property logger [Logger] Logger used for logging messages.
 * @property graphQLClient [GraphQLClient] Optional GraphQL client to use. Mainly used for unit testing.
 * @property signInGuard [SignInGuard] Optional SignInGuard to use. Mainly used for unit testing.
 * @property credentialManager [CredentialManager] Optional CredentialManager to use. Mainly used for unit testing.
 */
class DefaultSudoIdentityVerificationClient(
    private val context: Context,
    private val sudoUserClient: SudoUserClient,
    private val logger: Logger = DefaultLogger.instance,
    graphQLClient: GraphQLClient? = null,
    signInGuard: SignInGuard? = null,
    credentialManager: CredentialManager? = null,
) : SudoIdentityVerificationClient {
    companion object {
        private const val KNOWLEDGE_OF_PII = "KNOWLEDGE_OF_PII"
        private const val GOVERNMENT_ID = "GOVERNMENT_ID"

        /** Errors returned from the service */
        private const val SERVER_ERROR = "ServerError"
        private const val SERVICE_ERROR = "ServiceError"
        private const val ERROR_RECORD_NOT_FOUND = "IdentityVerificationRecordNotFoundError"
        private const val ERROR_UPDATE_FAILED = "IdentityVerificationUpdateFailedError"
        private const val ERROR_UNSUPPORTED_VERIFICATION_METHOD =
            "UnsupportedVerificationMethodError"
        private const val ERROR_IMPLAUSIBLE_AGE = "ImplausibleAgeError"
        private const val ERROR_INVALID_AGE = "InvalidAgeError"
        private const val ERROR_UNSUPPORTED_COUNTRY = "UnsupportedCountryError"
        private const val ERROR_UNSUPPORTED_NETWORK_LOCATION = "UnsupportedNetworkLocationError"
        private const val ERROR_REQUIRED_IDENTITY_INFORMATION_NOT_PROVIDED =
            "RequiredIdentityInformationNotProvidedError"
        private const val ERROR_IDENTITY_ALREADY_VERIFIED = "IdentityAlreadyVerifiedError"
        private const val ERROR_IDENTITY_CAPTURE_RETRIES_EXCEEDED =
            "IdentityCaptureRetriesExceededError"
        private const val ERROR_IDENTITY_CAPTURE_RETRY_BLOCKED = "IdentityCaptureRetryBlockedError"
        private const val ERROR_IDENTITY_DATA_REDACTED = "IdentityDataRedactedError"
        private const val ERROR_CONSENT_REQUIRED = "ConsentRequiredError"
        private const val ERROR_DIGITAL_CREDENTIAL_RESIDENTIAL_ADDRESS_REQUIRED =
            "DigitalCredentialResidentialAddressRequiredError"
        private const val ERROR_DIGITAL_CREDENTIAL_VERIFICATION_FAILED =
            "DigitalCredentialVerificationFailedError"
        private const val ERROR_DIGITAL_CREDENTIAL_ISSUER_NOT_TRUSTED =
            "DigitalCredentialIssuerNotTrustedError"
        private const val ERROR_DIGITAL_CREDENTIAL_NOT_ACCEPTED = "DigitalCredentialNotAcceptedError"
        private const val ERROR_DIGITAL_CREDENTIAL_NO_LONGER_VALID =
            "DigitalCredentialNoLongerValidError"
    }

    /**
     * Mutex for thread-safe access to the sign-in callback.
     */
    private val callbackMutex = Mutex()

    /**
     * Threadsafe container for optional callback to be invoked when operations are attempted while not signed in.
     */
    private var signInGuard = signInGuard ?: SignInGuard(sudoUserClient)

    override val version: String = "22.0.0"

    /**
     * GraphQL client used for calling Sudo service API.
     */
    private val graphQLClient: GraphQLClient

    private val credentialManager: CredentialManager by lazy {
        credentialManager ?: CredentialManager.create(context)
    }

    init {
        this.graphQLClient = graphQLClient ?: ApiClientManager.getClient(
            context,
            this.sudoUserClient,
        )
    }

    override fun setSignInCallback(callback: SudoPlatformSignInCallback?) {
        runBlocking {
            callbackMutex.withLock {
                signInGuard.setCallback(callback)
            }
        }
    }

    /**
     * Checks if the user is signed in and invokes the callback if needed.
     * Only performs the check if a callback is configured.
     *
     * This method implements the automatic sign-in checking mechanism:
     * If no callback is set, checks if user is signed in and throws NotSignedInException if not
     * If callback is set, checks if user is signed in using sudoUserClient.getSubject()
     * If user is not signed in, invokes the callback
     * Any exceptions from the callback are propagated to the caller
     *
     * @throws SudoIdentityVerificationException.NotSignedInException if user is not signed in
     * @throws Exception Any exception thrown by the sign-in callback is propagated; if we are
     * still not signed in after the callback returns, a NotSignedInException is thrown.
     */
    private suspend fun ensureSignedIn() {
        signInGuard.ensureSignedIn()

        if (!this.sudoUserClient.isSignedIn()) {
            throw SudoIdentityVerificationException.NotSignedInException()
        }
    }

    override suspend fun listSupportedCountries(): List<String> {
        this.logger.info("Retrieving the list of supported countries for identity verification.")
        ensureSignedIn()

        try {
            val response =
                this.graphQLClient.query<GetIdentityVerificationCapabilitiesQuery, GetIdentityVerificationCapabilitiesQuery.Data>(
                    GetIdentityVerificationCapabilitiesQuery.OPERATION_DOCUMENT,
                    emptyMap(),
                )

            if (response.hasErrors()) {
                logger.warning("errors = ${response.errors}")
                throw interpretSudoIdentityVerificationError(response.errors.first())
            }

            return response.data?.getIdentityVerificationCapabilities?.supportedCountries
                ?: listOf()
        } catch (e: Throwable) {
            logger.warning("unexpected error $e")
            when (e) {
                is NotAuthorizedException -> throw SudoIdentityVerificationException.AuthenticationException(
                    cause = e,
                )
                else -> throw interpretSudoIdentityVerificationException(e)
            }
        }
    }

    override suspend fun isFaceImageRequiredWithDocumentVerification(): Boolean {
        this.logger.info("Retrieving the flag indicating if face images need to be provided with ID document verification.")
        ensureSignedIn()

        try {
            val response =
                this.graphQLClient.query<GetIdentityVerificationCapabilitiesQuery, GetIdentityVerificationCapabilitiesQuery.Data>(
                    GetIdentityVerificationCapabilitiesQuery.OPERATION_DOCUMENT,
                    emptyMap(),
                )

            if (response.hasErrors()) {
                logger.warning("errors = ${response.errors}")
                throw interpretSudoIdentityVerificationError(response.errors.first())
            }

            return response.data?.getIdentityVerificationCapabilities?.faceImageRequiredWithDocumentVerification
                ?: false
        } catch (e: Throwable) {
            logger.warning("unexpected error $e")
            when (e) {
                is NotAuthorizedException -> throw SudoIdentityVerificationException.AuthenticationException(
                    cause = e,
                )
                else -> throw interpretSudoIdentityVerificationException(e)
            }
        }
    }

    override suspend fun isFaceImageRequiredWithDocumentCapture(): Boolean {
        this.logger.info("Retrieving the flag indicating if face images need to be provided with ID document capture.")
        ensureSignedIn()

        try {
            val response =
                this.graphQLClient.query<GetIdentityVerificationCapabilitiesQuery, GetIdentityVerificationCapabilitiesQuery.Data>(
                    GetIdentityVerificationCapabilitiesQuery.OPERATION_DOCUMENT,
                    emptyMap(),
                )

            if (response.hasErrors()) {
                logger.warning("errors = ${response.errors}")
                throw interpretSudoIdentityVerificationError(response.errors.first())
            }

            return response.data?.getIdentityVerificationCapabilities?.faceImageRequiredWithDocumentCapture
                ?: false
        } catch (e: Throwable) {
            logger.warning("unexpected error $e")
            when (e) {
                is NotAuthorizedException -> throw SudoIdentityVerificationException.AuthenticationException(
                    cause = e,
                )
                else -> throw interpretSudoIdentityVerificationException(e)
            }
        }
    }

    override suspend fun isDocumentCaptureInitiationEnabled(): Boolean {
        this.logger.info("Retrieves the flag for whether document capture can be initiated using initiateIdentityDocumentCapture()")
        ensureSignedIn()

        try {
            val response =
                this.graphQLClient.query<GetIdentityVerificationCapabilitiesQuery, GetIdentityVerificationCapabilitiesQuery.Data>(
                    GetIdentityVerificationCapabilitiesQuery.OPERATION_DOCUMENT,
                    emptyMap(),
                )

            if (response.hasErrors()) {
                logger.warning("errors = ${response.errors}")
                throw interpretSudoIdentityVerificationError(response.errors.first())
            }

            return response.data?.getIdentityVerificationCapabilities?.canInitiateDocumentCapture
                ?: false
        } catch (e: Throwable) {
            logger.warning("unexpected error $e")
            when (e) {
                is NotAuthorizedException -> throw SudoIdentityVerificationException.AuthenticationException(
                    cause = e,
                )
                else -> throw interpretSudoIdentityVerificationException(e)
            }
        }
    }

    override suspend fun isConsentRequiredForVerification(): Boolean {
        this.logger.info("Retrieves the flag for whether consent is required for verification.")
        ensureSignedIn()

        try {
            val response =
                this.graphQLClient.query<GetIdentityVerificationCapabilitiesQuery, GetIdentityVerificationCapabilitiesQuery.Data>(
                    GetIdentityVerificationCapabilitiesQuery.OPERATION_DOCUMENT,
                    emptyMap(),
                )

            if (response.hasErrors()) {
                logger.warning("errors = ${response.errors}")
                throw interpretSudoIdentityVerificationError(response.errors.first())
            }

            return response.data?.getIdentityVerificationCapabilities?.consentRequired
                ?: false
        } catch (e: Throwable) {
            logger.warning("unexpected error $e")
            when (e) {
                is NotAuthorizedException -> throw SudoIdentityVerificationException.AuthenticationException(
                    cause = e,
                )
                else -> throw interpretSudoIdentityVerificationException(e)
            }
        }
    }

    override suspend fun isDigitalCredentialVerificationEnabled(): Boolean {
        logger.info("Checking if identity verification with a digital credential is enabled.")
        ensureSignedIn()

        try {
            val response =
                this.graphQLClient.query<GetIdentityVerificationCapabilitiesQuery, GetIdentityVerificationCapabilitiesQuery.Data>(
                    GetIdentityVerificationCapabilitiesQuery.OPERATION_DOCUMENT,
                    emptyMap(),
                )

            if (response.hasErrors()) {
                logger.warning("errors = ${response.errors}")
                throw interpretSudoIdentityVerificationError(response.errors.first())
            }

            return response.data?.getIdentityVerificationCapabilities?.canVerifyWithDigitalCredential
                ?: false
        } catch (e: Throwable) {
            logger.warning("unexpected error $e")
            when (e) {
                is NotAuthorizedException -> throw SudoIdentityVerificationException.AuthenticationException(
                    cause = e,
                )
                else -> throw interpretSudoIdentityVerificationException(e)
            }
        }
    }

    override suspend fun checkIdentityVerification(): VerifiedIdentity {
        this.logger.info("Checking the identity verification status.")
        ensureSignedIn()

        try {
            val response =
                this.graphQLClient.query<CheckIdentityVerificationQuery, CheckIdentityVerificationQuery.Data>(
                    CheckIdentityVerificationQuery.OPERATION_DOCUMENT,
                    emptyMap(),
                )

            if (response.hasErrors()) {
                logger.warning("errors = ${response.errors}")
                throw interpretSudoIdentityVerificationError(response.errors.first())
            }
            val result = response.data?.checkIdentityVerification?.verifiedIdentity
            result?.let {
                return VerifiedIdentityTransformer.toEntity(result)
            }
            throw SudoIdentityVerificationException.FailedException("Query succeeded but output was null.")
        } catch (e: Throwable) {
            logger.warning("unexpected error $e")
            when (e) {
                is NotAuthorizedException -> throw SudoIdentityVerificationException.AuthenticationException(
                    cause = e,
                )
                else -> throw interpretSudoIdentityVerificationException(e)
            }
        }
    }

    override suspend fun verifyIdentity(input: VerifyIdentityInput): VerifiedIdentity {
        this.logger.info("Verifying an identity.")
        ensureSignedIn()

        try {
            val mutationInput =
                VerifyIdentityMutationInput(
                    verificationMethod = KNOWLEDGE_OF_PII,
                    firstName = input.firstName,
                    lastName = input.lastName,
                    address = input.address,
                    city = Optional.presentIfNotNull(input.city),
                    state = Optional.presentIfNotNull(input.state),
                    postalCode = input.postalCode,
                    country = input.country,
                    dateOfBirth = input.dateOfBirth,
                )

            val response =
                this.graphQLClient.mutate<VerifyIdentityMutation, VerifyIdentityMutation.Data>(
                    VerifyIdentityMutation.OPERATION_DOCUMENT,
                    mapOf("input" to Optional.presentIfNotNull(mutationInput)),
                )

            if (response.hasErrors()) {
                logger.warning("errors = ${response.errors}")
                throw interpretSudoIdentityVerificationError(response.errors.first())
            }
            val result = response.data?.verifyIdentity?.verifiedIdentity
            result?.let {
                return VerifiedIdentityTransformer.toEntity(result)
            }
            throw SudoIdentityVerificationException.FailedException("Mutation succeeded but output was null.")
        } catch (e: Throwable) {
            logger.warning("unexpected error $e")
            when (e) {
                is NotAuthorizedException -> throw SudoIdentityVerificationException.AuthenticationException(
                    cause = e,
                )
                else -> throw interpretSudoIdentityVerificationException(e)
            }
        }
    }

    override suspend fun verifyIdentityDocument(input: VerifyIdentityDocumentInput): VerifiedIdentity {
        this.logger.info("Verifying identity document.")
        ensureSignedIn()

        try {
            val mutationInput =
                VerifyIdentityDocumentMutationInput(
                    verificationMethod = GOVERNMENT_ID,
                    imageBase64 = input.imageBase64,
                    backImageBase64 = input.backImageBase64,
                    faceImageBase64 = Optional.presentIfNotNull(input.faceImageBase64),
                    country = input.country,
                    documentType = input.documentType.type,
                )

            val response =
                this.graphQLClient.mutate<VerifyIdentityDocumentMutation, VerifyIdentityDocumentMutation.Data>(
                    VerifyIdentityDocumentMutation.OPERATION_DOCUMENT,
                    mapOf("input" to Optional.presentIfNotNull(mutationInput)),
                )

            if (response.hasErrors()) {
                logger.warning("errors = ${response.errors}")
                throw interpretSudoIdentityVerificationError(response.errors.first())
            }
            val result = response.data?.verifyIdentityDocument?.verifiedIdentity
            result?.let {
                return VerifiedIdentityTransformer.toEntity(result)
            }
            throw SudoIdentityVerificationException.FailedException("Mutation succeeded but output was null.")
        } catch (e: Throwable) {
            logger.warning("unexpected error $e")
            when (e) {
                is NotAuthorizedException -> throw SudoIdentityVerificationException.AuthenticationException(
                    cause = e,
                )
                else -> throw interpretSudoIdentityVerificationException(e)
            }
        }
    }

    override suspend fun captureAndVerifyIdentityDocument(input: VerifyIdentityDocumentInput): VerifiedIdentity {
        this.logger.info("Capturing and verifying identity document.")
        ensureSignedIn()

        try {
            val mutationInput =
                VerifyIdentityDocumentMutationInput(
                    verificationMethod = GOVERNMENT_ID,
                    imageBase64 = input.imageBase64,
                    backImageBase64 = input.backImageBase64,
                    faceImageBase64 = Optional.presentIfNotNull(input.faceImageBase64),
                    country = input.country,
                    documentType = input.documentType.type,
                )
            val response =
                this.graphQLClient.mutate<CaptureAndVerifyIdentityDocumentMutation, CaptureAndVerifyIdentityDocumentMutation.Data>(
                    CaptureAndVerifyIdentityDocumentMutation.OPERATION_DOCUMENT,
                    mapOf("input" to Optional.presentIfNotNull(mutationInput)),
                )

            if (response.hasErrors()) {
                logger.warning("errors = ${response.errors}")
                throw interpretSudoIdentityVerificationError(response.errors.first())
            }
            val result = response.data?.captureAndVerifyIdentityDocument?.verifiedIdentity
            result?.let {
                return VerifiedIdentityTransformer.toEntity(result)
            }
            throw SudoIdentityVerificationException.FailedException("Mutation succeeded but output was null.")
        } catch (e: Throwable) {
            logger.warning("unexpected error $e")
            when (e) {
                is NotAuthorizedException -> throw SudoIdentityVerificationException.AuthenticationException(
                    cause = e,
                )
                else -> throw interpretSudoIdentityVerificationException(e)
            }
        }
    }

    @RequiresApi(Build.VERSION_CODES.P)
    override suspend fun verifyIdentityWithDigitalCredential(activity: Activity): DigitalCredentialVerificationOutcome {
        logger.info("Verifying identity with a digital credential.")
        ensureSignedIn()

        try {
            val request = initiateDigitalCredentialVerification(getAppOrigin())
            val requestJson =
                request.flow.onDcApiFlowRequest?.requestJson
                    ?: throw SudoIdentityVerificationException.FailedException(
                        "Unexpected digital credential flow: ${request.flow.__typename}",
                    )

            val credentialJson = getDigitalCredential(activity, requestJson)
            val expiresAt = Instant.ofEpochMilli((request.expiryAtEpochSeconds * 1000).toLong())
            // The service would reject an expired session anyway, but only with an untyped error.
            ensureNotExpired(expiresAt)

            val verifiedIdentity =
                finalizeDigitalCredentialVerification(credentialJson, null)
                    ?: return DigitalCredentialVerificationOutcome.ResidentialAddressRequired(
                        response = credentialJson,
                        expiresAt = expiresAt,
                    )
            return DigitalCredentialVerificationOutcome.Completed(verifiedIdentity)
        } catch (e: Throwable) {
            logger.warning("unexpected error $e")
            when (e) {
                is NotAuthorizedException -> throw SudoIdentityVerificationException.AuthenticationException(
                    cause = e,
                )
                else -> throw interpretSudoIdentityVerificationException(e)
            }
        }
    }

    override suspend fun completeDigitalCredentialVerification(
        pending: DigitalCredentialVerificationOutcome.ResidentialAddressRequired,
        address: ResidentialAddressInput,
    ): VerifiedIdentity {
        logger.info("Completing a digital credential verification with a residential address.")
        ensureSignedIn()

        try {
            // The service would reject an expired session anyway, but only with an untyped error.
            ensureNotExpired(pending.expiresAt)

            return finalizeDigitalCredentialVerification(pending.response, address)
                // The service asks for an address only for a submission without one.
                ?: throw SudoIdentityVerificationException.FailedException(
                    "Service required a residential address although one was supplied.",
                )
        } catch (e: Throwable) {
            logger.warning("unexpected error $e")
            when (e) {
                is NotAuthorizedException -> throw SudoIdentityVerificationException.AuthenticationException(
                    cause = e,
                )
                else -> throw interpretSudoIdentityVerificationException(e)
            }
        }
    }

    /**
     * The service binds the presentation request to this origin, which must match the origin the
     * wallet reports for the calling app, so it is derived from the app's signing certificate in
     * the `android:apk-key-hash:` form: the SHA-256 digest of the certificate in standard Base64
     * without padding.
     */
    @RequiresApi(Build.VERSION_CODES.P)
    private fun getAppOrigin(): String {
        val packageInfo =
            context.packageManager.getPackageInfo(
                context.packageName,
                PackageManager.GET_SIGNING_CERTIFICATES,
            )
        val signer =
            packageInfo.signingInfo?.apkContentsSigners?.firstOrNull()
                ?: throw SudoIdentityVerificationException.FailedException("Unable to determine app signing certificate.")
        val digest = MessageDigest.getInstance("SHA-256").digest(signer.toByteArray())
        return "android:apk-key-hash:${Base64.getEncoder().withoutPadding().encodeToString(digest)}"
    }

    private suspend fun initiateDigitalCredentialVerification(
        origin: String,
    ): InitiateDigitalCredentialVerificationMutation.InitiateDigitalCredentialVerification {
        val mutationInput =
            InitiateDigitalCredentialVerificationInput(
                flow = DigitalCredentialFlow.DC_API,
                origin = Optional.presentIfNotNull(origin),
            )
        val response =
            this.graphQLClient.mutate<InitiateDigitalCredentialVerificationMutation, InitiateDigitalCredentialVerificationMutation.Data>(
                InitiateDigitalCredentialVerificationMutation.OPERATION_DOCUMENT,
                mapOf("input" to Optional.presentIfNotNull(mutationInput)),
            )

        if (response.hasErrors()) {
            logger.warning("errors = ${response.errors}")
            throw interpretSudoIdentityVerificationError(response.errors.first())
        }
        return response.data?.initiateDigitalCredentialVerification
            ?: throw SudoIdentityVerificationException.FailedException("Mutation succeeded but output was null.")
    }

    @OptIn(ExperimentalDigitalCredentialApi::class)
    private suspend fun getDigitalCredential(
        activity: Activity,
        requestJson: String,
    ): String {
        val request = GetCredentialRequest(listOf(GetDigitalCredentialOption(requestJson = requestJson)))
        val result =
            try {
                credentialManager.getCredential(activity, request)
            } catch (e: GetCredentialException) {
                throw interpretGetCredentialException(e)
            }
        val credential =
            result.credential as? DigitalCredential
                ?: throw SudoIdentityVerificationException.FailedException(
                    "Unexpected credential type: ${result.credential.type}",
                )
        return credential.credentialJson
    }

    /**
     * Submits a wallet response, with the user's residential address if given.
     *
     * @return The verification result, or null if the service requires a residential address
     *  that the credential does not carry and none was given. The response may then be
     *  submitted again with an address.
     */
    private suspend fun finalizeDigitalCredentialVerification(
        credentialJson: String,
        address: ResidentialAddressInput?,
    ): VerifiedIdentity? {
        val mutationInput =
            FinalizeDigitalCredentialVerificationInput(
                response = credentialJson,
                residentialAddress =
                    Optional.presentIfNotNull(
                        address?.let {
                            DigitalCredentialResidentialAddressInput(
                                address = it.address,
                                city = Optional.presentIfNotNull(it.city),
                                state = Optional.presentIfNotNull(it.state),
                                postalCode = it.postalCode,
                                country = it.country,
                            )
                        },
                    ),
            )
        val response =
            this.graphQLClient.mutate<FinalizeDigitalCredentialVerificationMutation, FinalizeDigitalCredentialVerificationMutation.Data>(
                FinalizeDigitalCredentialVerificationMutation.OPERATION_DOCUMENT,
                mapOf("input" to Optional.presentIfNotNull(mutationInput)),
            )

        if (response.hasErrors()) {
            logger.warning("errors = ${response.errors}")
            val error = response.errors.first()
            val errorType = error.extensions?.get(GRAPHQL_ERROR_TYPE)?.toString() ?: ""
            if (errorType.contains(ERROR_DIGITAL_CREDENTIAL_RESIDENTIAL_ADDRESS_REQUIRED)) {
                return null
            }
            throw interpretSudoIdentityVerificationError(error)
        }
        val result =
            response.data?.finalizeDigitalCredentialVerification?.verifiedIdentity
                ?: throw SudoIdentityVerificationException.FailedException("Mutation succeeded but output was null.")
        return VerifiedIdentityTransformer.toEntity(result)
    }

    private fun ensureNotExpired(expiresAt: Instant) {
        if (!Instant.now().isBefore(expiresAt)) {
            throw SudoIdentityVerificationException.DigitalCredentialRequestExpiredException(
                "Digital credential request has expired.",
            )
        }
    }

    private fun interpretGetCredentialException(e: GetCredentialException): SudoIdentityVerificationException =
        when (e) {
            is GetCredentialCancellationException ->
                SudoIdentityVerificationException.DigitalCredentialCancelledException(e.message, e)
            is NoCredentialException ->
                SudoIdentityVerificationException.NoDigitalCredentialException(e.message, e)
            is GetCredentialUnsupportedException,
            is GetCredentialProviderConfigurationException,
            ->
                SudoIdentityVerificationException.DigitalCredentialUnsupportedException(e.message, e)
            else -> SudoIdentityVerificationException.FailedException(e.message, e)
        }

    override suspend fun initiateIdentityDocumentCapture(): IdentityDocumentCaptureInitiationInfo {
        this.logger.info("Attempts to initiate ID document capture using underlying provider's web based method.")
        ensureSignedIn()

        try {
            val response =
                this.graphQLClient.mutate<InitiateIdentityDocumentCaptureMutation, InitiateIdentityDocumentCaptureMutation.Data>(
                    InitiateIdentityDocumentCaptureMutation.OPERATION_DOCUMENT,
                    emptyMap(),
                )

            if (response.hasErrors()) {
                logger.warning("errors = ${response.errors}")
                throw interpretSudoIdentityVerificationError(response.errors.first())
            }
            val result = response.data?.initiateIdentityDocumentCapture
            result?.let {
                return IdentityDocumentCaptureInitiationInfoTransformer.toEntity(result)
            }
            throw SudoIdentityVerificationException.FailedException("Mutation succeeded but output was null.")
        } catch (e: Throwable) {
            logger.warning("unexpected error $e")
            when (e) {
                is NotAuthorizedException -> throw SudoIdentityVerificationException.AuthenticationException(
                    cause = e,
                )
                else -> throw interpretSudoIdentityVerificationException(e)
            }
        }
    }

    override suspend fun provideIdentityDataProcessingConsent(input: IdentityDataProcessingConsentInput): Boolean {
        this.logger.info("Providing identity data processing consent.")
        ensureSignedIn()

        try {
            val mutationInput =
                GraphQLIdentityDataProcessingConsentInput(
                    content = input.content,
                    contentType = input.contentType,
                    language = input.language,
                )
            val response =
                this.graphQLClient.mutate<ProvideIdentityDataProcessingConsentMutation, ProvideIdentityDataProcessingConsentMutation.Data>(
                    ProvideIdentityDataProcessingConsentMutation.OPERATION_DOCUMENT,
                    mapOf("input" to mutationInput),
                )

            if (response.hasErrors()) {
                logger.warning("errors = ${response.errors}")
                throw interpretSudoIdentityVerificationError(response.errors.first())
            }
            val result = response.data?.provideIdentityDataProcessingConsent
            result?.let {
                return result.processed
            }
            throw SudoIdentityVerificationException.FailedException("Mutation succeeded but output was null.")
        } catch (e: Throwable) {
            logger.warning("unexpected error $e")
            when (e) {
                is NotAuthorizedException -> throw SudoIdentityVerificationException.AuthenticationException(
                    cause = e,
                )
                else -> throw interpretSudoIdentityVerificationException(e)
            }
        }
    }

    override suspend fun withdrawIdentityDataProcessingConsent(): Boolean {
        this.logger.info("Withdrawing identity data processing consent.")
        ensureSignedIn()

        try {
            val response =
                this.graphQLClient
                    .mutate<WithdrawIdentityDataProcessingConsentMutation, WithdrawIdentityDataProcessingConsentMutation.Data>(
                        WithdrawIdentityDataProcessingConsentMutation.OPERATION_DOCUMENT,
                        emptyMap(),
                    )

            if (response.hasErrors()) {
                logger.warning("errors = ${response.errors}")
                throw interpretSudoIdentityVerificationError(response.errors.first())
            }
            val result = response.data?.withdrawIdentityDataProcessingConsent
            result?.let {
                return result.processed
            }
            throw SudoIdentityVerificationException.FailedException("Mutation succeeded but output was null.")
        } catch (e: Throwable) {
            logger.warning("unexpected error $e")
            when (e) {
                is NotAuthorizedException -> throw SudoIdentityVerificationException.AuthenticationException(
                    cause = e,
                )
                else -> throw interpretSudoIdentityVerificationException(e)
            }
        }
    }

    override suspend fun getIdentityDataProcessingConsentContent(
        input: IdentityDataProcessingConsentContentInput,
    ): IdentityDataProcessingConsentContent {
        this.logger.info("Retrieving identity data processing consent content.")
        ensureSignedIn()

        try {
            val queryInput =
                GraphQLIdentityDataProcessingConsentContentInput(
                    preferredLanguage = input.preferredLanguage,
                    preferredContentType = input.preferredContentType,
                )
            val response =
                this.graphQLClient.query<GetIdentityDataProcessingConsentContentQuery, GetIdentityDataProcessingConsentContentQuery.Data>(
                    GetIdentityDataProcessingConsentContentQuery.OPERATION_DOCUMENT,
                    mapOf(
                        "input" to queryInput,
                    ),
                )

            if (response.hasErrors()) {
                logger.warning("errors = ${response.errors}")
                throw interpretSudoIdentityVerificationError(response.errors.first())
            }
            val result = response.data?.getIdentityDataProcessingConsentContent
            result?.let {
                return IdentityDataProcessingConsentContent(
                    content = it.content,
                    contentType = it.contentType,
                    language = it.language,
                )
            }
            throw SudoIdentityVerificationException.FailedException("Query succeeded but output was null.")
        } catch (e: Throwable) {
            logger.warning("unexpected error $e")
            when (e) {
                is NotAuthorizedException -> throw SudoIdentityVerificationException.AuthenticationException(
                    cause = e,
                )
                else -> throw interpretSudoIdentityVerificationException(e)
            }
        }
    }

    override suspend fun getIdentityDataProcessingConsentStatus(): IdentityDataProcessingConsentStatus {
        logger.info("Retrieving identity data processing consent status.")
        ensureSignedIn()

        try {
            val response =
                this.graphQLClient.query<GetIdentityDataProcessingConsentStatusQuery, GetIdentityDataProcessingConsentStatusQuery.Data>(
                    GetIdentityDataProcessingConsentStatusQuery.OPERATION_DOCUMENT,
                    emptyMap(),
                )

            if (response.hasErrors()) {
                logger.warning("errors = ${response.errors}")
                throw interpretSudoIdentityVerificationError(response.errors.first())
            }
            val result = response.data?.getIdentityDataProcessingConsentStatus
            result?.let {
                return IdentityDataProcessingConsentStatus(
                    consented = it.consented,
                    consentedAtEpochMs = it.consentedAtEpochMs,
                    consentWithdrawnAtEpochMs = it.consentWithdrawnAtEpochMs,
                    content = it.content,
                    contentType = it.contentType,
                    language = it.language,
                )
            }
            throw SudoIdentityVerificationException.FailedException("Query succeeded but output was null.")
        } catch (e: Throwable) {
            logger.warning("unexpected error $e")
            when (e) {
                is NotAuthorizedException -> throw SudoIdentityVerificationException.AuthenticationException(
                    cause = e,
                )
                else -> throw interpretSudoIdentityVerificationException(e)
            }
        }
    }

    override fun reset() {
        this.logger.info("Resetting client.")
    }

    private fun interpretSudoIdentityVerificationError(e: GraphQLResponse.Error): SudoIdentityVerificationException {
        val httpStatusCode = e.extensions?.get(HTTP_STATUS_CODE_KEY) as Int?
        val error = e.extensions?.get(GRAPHQL_ERROR_TYPE)?.toString() ?: ""

        if (httpStatusCode == HttpURLConnection.HTTP_UNAUTHORIZED) {
            return SudoIdentityVerificationException.AuthenticationException(e.message)
        } else if (httpStatusCode != null && httpStatusCode >= HttpURLConnection.HTTP_INTERNAL_ERROR) {
            return SudoIdentityVerificationException.FailedException(e.message)
        }
        if (error.contains(SERVER_ERROR) || error.contains(SERVICE_ERROR)) {
            return SudoIdentityVerificationException.InternalServerException(message = error)
        } else if (error.contains(ERROR_RECORD_NOT_FOUND)) {
            return SudoIdentityVerificationException.IdentityVerificationRecordNotFoundException(
                message = error,
            )
        } else if (error.contains(ERROR_UPDATE_FAILED)) {
            return SudoIdentityVerificationException.IdentityVerificationUpdateFailedException(
                message = error,
            )
        } else if (error.contains(ERROR_UNSUPPORTED_VERIFICATION_METHOD)) {
            return SudoIdentityVerificationException.UnsupportedVerificationMethodException(message = error)
        } else if (error.contains(ERROR_IMPLAUSIBLE_AGE)) {
            return SudoIdentityVerificationException.ImplausibleAgeException(message = error)
        } else if (error.contains(ERROR_INVALID_AGE)) {
            return SudoIdentityVerificationException.InvalidAgeException(message = error)
        } else if (error.contains(ERROR_CONSENT_REQUIRED)) {
            return SudoIdentityVerificationException.ConsentRequiredException(message = error)
        } else if (error.contains(ERROR_UNSUPPORTED_COUNTRY)) {
            return SudoIdentityVerificationException.UnsupportedCountryException(message = error)
        } else if (error.contains(ERROR_UNSUPPORTED_NETWORK_LOCATION)) {
            return SudoIdentityVerificationException.UnsupportedNetworkLocationException(message = error)
        } else if (error.contains(ERROR_REQUIRED_IDENTITY_INFORMATION_NOT_PROVIDED)) {
            return SudoIdentityVerificationException.RequiredIdentityInformationNotProvidedException(message = error)
        } else if (error.contains(ERROR_IDENTITY_ALREADY_VERIFIED)) {
            return SudoIdentityVerificationException.IdentityAlreadyVerifiedException(message = error)
        } else if (error.contains(ERROR_IDENTITY_CAPTURE_RETRIES_EXCEEDED)) {
            return SudoIdentityVerificationException.IdentityCaptureRetriesExceededException(message = error)
        } else if (error.contains(ERROR_IDENTITY_CAPTURE_RETRY_BLOCKED)) {
            return SudoIdentityVerificationException.IdentityCaptureRetryBlockedException(message = error)
        } else if (error.contains(ERROR_IDENTITY_DATA_REDACTED)) {
            return SudoIdentityVerificationException.IdentityDataRedactedException(message = error)
        } else if (error.contains(ERROR_DIGITAL_CREDENTIAL_VERIFICATION_FAILED)) {
            return SudoIdentityVerificationException.DigitalCredentialVerificationFailedException(message = error)
        } else if (error.contains(ERROR_DIGITAL_CREDENTIAL_ISSUER_NOT_TRUSTED)) {
            return SudoIdentityVerificationException.DigitalCredentialIssuerNotTrustedException(message = error)
        } else if (error.contains(ERROR_DIGITAL_CREDENTIAL_NOT_ACCEPTED)) {
            return SudoIdentityVerificationException.DigitalCredentialNotAcceptedException(message = error)
        } else if (error.contains(ERROR_DIGITAL_CREDENTIAL_NO_LONGER_VALID)) {
            return SudoIdentityVerificationException.DigitalCredentialNoLongerValidException(message = error)
        }
        return SudoIdentityVerificationException.FailedException(e.toString())
    }

    private fun interpretSudoIdentityVerificationException(e: Throwable): Throwable =
        when (e) {
            is CancellationException,
            is SudoIdentityVerificationException,
            -> e
            else -> SudoIdentityVerificationException.UnknownException(e)
        }
}
