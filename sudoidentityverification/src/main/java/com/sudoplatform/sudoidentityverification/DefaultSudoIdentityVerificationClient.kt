/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoidentityverification

import android.content.Context
import com.amazonaws.services.cognitoidentity.model.NotAuthorizedException
import com.amplifyframework.api.graphql.GraphQLResponse
import com.apollographql.apollo.api.Optional
import com.sudoplatform.sudoapiclient.ApiClientManager
import com.sudoplatform.sudoidentityverification.graphql.CaptureAndVerifyIdentityDocumentMutation
import com.sudoplatform.sudoidentityverification.graphql.CheckIdentityVerificationQuery
import com.sudoplatform.sudoidentityverification.graphql.GetIdentityVerificationCapabilitiesQuery
import com.sudoplatform.sudoidentityverification.graphql.InitiateIdentityDocumentCaptureMutation
import com.sudoplatform.sudoidentityverification.graphql.VerifyIdentityDocumentMutation
import com.sudoplatform.sudoidentityverification.graphql.VerifyIdentityMutation
import com.sudoplatform.sudoidentityverification.types.IdentityDocumentCaptureInitiationInfo
import com.sudoplatform.sudoidentityverification.types.IdentityDocumentCaptureInitiationInfoTransformer
import com.sudoplatform.sudoidentityverification.types.VerifiedIdentity
import com.sudoplatform.sudoidentityverification.types.VerifiedIdentityTransformer
import com.sudoplatform.sudoidentityverification.types.inputs.VerifyIdentityDocumentInput
import com.sudoplatform.sudoidentityverification.types.inputs.VerifyIdentityInput
import com.sudoplatform.sudologging.Logger
import com.sudoplatform.sudouser.SudoUserClient
import com.sudoplatform.sudouser.amplify.GraphQLClient
import com.sudoplatform.sudouser.exceptions.GRAPHQL_ERROR_TYPE
import com.sudoplatform.sudouser.exceptions.HTTP_STATUS_CODE_KEY
import java.net.HttpURLConnection
import java.util.concurrent.CancellationException
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
 */
class DefaultSudoIdentityVerificationClient(
    private val context: Context,
    private val sudoUserClient: SudoUserClient,
    private val logger: Logger = DefaultLogger.instance,
    graphQLClient: GraphQLClient? = null,
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
    }

    override val version: String = "18.1.0"

    /**
     * GraphQL client used for calling Sudo service API.
     */
    private val graphQLClient: GraphQLClient

    init {
        this.graphQLClient = graphQLClient ?: ApiClientManager.getClient(
            context,
            this.sudoUserClient,
        )
    }

    override suspend fun listSupportedCountries(): List<String> {
        this.logger.info("Retrieving the list of supported countries for identity verification.")

        if (!this.sudoUserClient.isSignedIn()) {
            throw SudoIdentityVerificationException.NotSignedInException()
        }

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

        if (!this.sudoUserClient.isSignedIn()) {
            throw SudoIdentityVerificationException.NotSignedInException()
        }

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

        if (!this.sudoUserClient.isSignedIn()) {
            throw SudoIdentityVerificationException.NotSignedInException()
        }

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

        if (!this.sudoUserClient.isSignedIn()) {
            throw SudoIdentityVerificationException.NotSignedInException()
        }

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

    override suspend fun checkIdentityVerification(): VerifiedIdentity {
        this.logger.info("Checking the identity verification status.")

        if (!this.sudoUserClient.isSignedIn()) {
            throw SudoIdentityVerificationException.NotSignedInException()
        }

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

        if (!this.sudoUserClient.isSignedIn()) {
            throw SudoIdentityVerificationException.NotSignedInException()
        }

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

        if (!this.sudoUserClient.isSignedIn()) {
            throw SudoIdentityVerificationException.NotSignedInException()
        }

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

        if (!this.sudoUserClient.isSignedIn()) {
            throw SudoIdentityVerificationException.NotSignedInException()
        }

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

    override suspend fun initiateIdentityDocumentCapture(): IdentityDocumentCaptureInitiationInfo {
        this.logger.info("Attempts to initiate ID document capture using underlying provider's web based method.")

        if (!this.sudoUserClient.isSignedIn()) {
            throw SudoIdentityVerificationException.NotSignedInException()
        }

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
