/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoidentityverification

import android.content.Context
import com.amazonaws.mobileconnectors.appsync.AWSAppSyncClient
import com.amazonaws.mobileconnectors.appsync.fetcher.AppSyncResponseFetchers
import com.amazonaws.services.cognitoidentity.model.NotAuthorizedException
import com.apollographql.apollo.api.Error
import com.apollographql.apollo.exception.ApolloException
import com.sudoplatform.sudoapiclient.ApiClientManager
import com.sudoplatform.sudoidentityverification.extensions.enqueue
import com.sudoplatform.sudoidentityverification.extensions.enqueueFirst
import com.sudoplatform.sudoidentityverification.types.VerifiedIdentity
import com.sudoplatform.sudoidentityverification.types.inputs.VerifyIdentityDocumentInput
import com.sudoplatform.sudoidentityverification.types.inputs.VerifyIdentityInput
import com.sudoplatform.sudologging.Logger
import com.sudoplatform.sudouser.SudoUserClient
import java.util.Date
import java.util.concurrent.CancellationException
import com.sudoplatform.sudoidentityverification.type.VerifyIdentityDocumentInput as VerifyIdentityDocumentRequest
import com.sudoplatform.sudoidentityverification.type.VerifyIdentityInput as VerifyIdentityRequest

/**
 * Default implementation of the [SudoIdentityVerificationClient] interface.
 *
 * @property context [Context] Application context.
 * @property sudoUserClient [SudoUserClient] Instance required to issue authentication tokens and perform
 *  cryptographic operations.
 * @property logger [Logger] Logger used for logging messages.
 * @property graphQLClient [AWSAppSyncClient] Optional GraphQL client to use. Mainly used for unit testing.
 */
class DefaultSudoIdentityVerificationClient(
    private val context: Context,
    private val sudoUserClient: SudoUserClient,
    private val logger: Logger = DefaultLogger.instance,
    graphQLClient: AWSAppSyncClient? = null,
) : SudoIdentityVerificationClient {

    companion object {
        private const val KNOWLEDGE_OF_PII = "KNOWLEDGE_OF_PII"
        private const val GOVERNMENT_ID = "GOVERNMENT_ID"

        /** Errors returned from the service */
        private const val ERROR_TYPE = "errorType"
        private const val SERVER_ERROR = "ServerError"
        private const val SERVICE_ERROR = "ServiceError"
        private const val ERROR_RECORD_NOT_FOUND = "IdentityVerificationRecordNotFoundError"
        private const val ERROR_UPDATE_FAILED = "IdentityVerificationUpdateFailedError"
        private const val ERROR_UNSUPPORTED_VERIFICATION_METHOD =
            "UnsupportedVerificationMethodError"
        private const val ERROR_IMPLAUSIBLE_AGE = "ImplausibleAgeError"
        private const val ERROR_INVALID_AGE = "InvalidAgeError"
        private const val ERROR_UNSUPPORTED_COUNTRY = "UnsupportedCountryError"
    }

    override val version: String = "13.0.0"

    /**
     * GraphQL client used for calling Sudo service API.
     */
    private val graphQLClient: AWSAppSyncClient

    init {
        @Suppress("UNCHECKED_CAST")
        this.graphQLClient = graphQLClient ?: ApiClientManager.getClient(
            context,
            this.sudoUserClient,
        )
    }

    override suspend fun listSupportedCountries(): List<String> {
        this.logger.info("Retrieving the list of supports countries for identity verification.")

        if (!this.sudoUserClient.isSignedIn()) {
            throw SudoIdentityVerificationException.NotSignedInException()
        }

        try {
            val query = GetSupportedCountriesForIdentityVerificationQuery.builder()
                .build()

            val response = this.graphQLClient.query(query)
                .enqueueFirst()

            if (response.hasErrors()) {
                logger.warning("errors = ${response.errors()}")
                throw interpretSudoIdentityVerificationError(response.errors().first())
            }

            return response.data()?.supportedCountriesForIdentityVerification?.countryList()
                ?: listOf()
        } catch (e: Throwable) {
            logger.warning("unexpected error $e")
            when (e) {
                is NotAuthorizedException -> throw SudoIdentityVerificationException.AuthenticationException(
                    cause = e,
                )
                is ApolloException -> throw SudoIdentityVerificationException.FailedException(cause = e)
                else -> throw interpretSudoIdentityVerificationException(e)
            }
        }
    }

    override suspend fun checkIdentityVerification(option: QueryOption): VerifiedIdentity {
        this.logger.info("Checking the identity verification status.")

        if (!this.sudoUserClient.isSignedIn()) {
            throw SudoIdentityVerificationException.NotSignedInException()
        }

        try {
            val query = CheckIdentityVerificationQuery.builder()
                .build()

            val responseFetcher = when (option) {
                QueryOption.CACHE_ONLY -> {
                    AppSyncResponseFetchers.CACHE_ONLY
                }
                QueryOption.REMOTE_ONLY -> {
                    AppSyncResponseFetchers.NETWORK_ONLY
                }
            }

            val response = this.graphQLClient.query(query)
                .responseFetcher(responseFetcher)
                .enqueueFirst()

            if (response.hasErrors()) {
                logger.warning("errors = ${response.errors()}")
                throw interpretSudoIdentityVerificationError(response.errors().first())
            }
            val output = response.data()?.checkIdentityVerification()
            output?.let {
                var verifiedAt: Date? = null
                val verifiedAtEpochMs = output.verifiedAtEpochMs()
                if (verifiedAtEpochMs != null) {
                    verifiedAt = Date(verifiedAtEpochMs.toLong())
                }
                return VerifiedIdentity(
                    output.owner(),
                    output.verified(),
                    verifiedAt,
                    output.verificationMethod(),
                    output.canAttemptVerificationAgain(),
                    output.idScanUrl(),
                )
            }
            throw SudoIdentityVerificationException.FailedException("Query succeeded but output was null.")
        } catch (e: Throwable) {
            logger.warning("unexpected error $e")
            when (e) {
                is NotAuthorizedException -> throw SudoIdentityVerificationException.AuthenticationException(
                    cause = e,
                )
                is ApolloException -> throw SudoIdentityVerificationException.FailedException(cause = e)
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
            val mutationInput = VerifyIdentityRequest.builder()
                .verificationMethod(KNOWLEDGE_OF_PII)
                .firstName(input.firstName)
                .lastName(input.lastName)
                .address(input.address)
                .city(input.city)
                .state(input.state)
                .postalCode(input.postalCode)
                .country(input.country)
                .dateOfBirth(input.dateOfBirth)
                .build()
            val mutation = VerifyIdentityMutation.builder()
                .input(mutationInput)
                .build()

            val response = this.graphQLClient.mutate(mutation)
                .enqueue()

            if (response.hasErrors()) {
                logger.warning("errors = ${response.errors()}")
                throw interpretSudoIdentityVerificationError(response.errors().first())
            }
            val result = response.data()?.verifyIdentity()
            result?.let {
                var verifiedAt: Date? = null
                val verifiedAtEpochMs = result.verifiedAtEpochMs()
                if (verifiedAtEpochMs != null) {
                    verifiedAt = Date(verifiedAtEpochMs.toLong())
                }
                return VerifiedIdentity(
                    result.owner(),
                    result.verified(),
                    verifiedAt,
                    result.verificationMethod(),
                    result.canAttemptVerificationAgain(),
                    result.idScanUrl(),
                )
            }
            throw SudoIdentityVerificationException.FailedException("Mutation succeeded but output was null.")
        } catch (e: Throwable) {
            logger.warning("unexpected error $e")
            when (e) {
                is NotAuthorizedException -> throw SudoIdentityVerificationException.AuthenticationException(
                    cause = e,
                )
                is ApolloException -> throw SudoIdentityVerificationException.FailedException(cause = e)
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
            val mutationInput = VerifyIdentityDocumentRequest.builder()
                .verificationMethod(GOVERNMENT_ID)
                .imageBase64(input.imageBase64)
                .backImageBase64(input.backImageBase64)
                .country(input.country)
                .documentType(input.documentType.type)
                .build()
            val mutation = VerifyIdentityDocumentMutation.builder()
                .input(mutationInput)
                .build()

            val response = this.graphQLClient.mutate(mutation)
                .enqueue()

            if (response.hasErrors()) {
                logger.warning("errors = ${response.errors()}")
                throw interpretSudoIdentityVerificationError(response.errors().first())
            }
            val result = response.data()?.verifyIdentityDocument()
            result?.let {
                var verifiedAt: Date? = null
                val verifiedAtEpochMs = result.verifiedAtEpochMs()
                if (verifiedAtEpochMs != null) {
                    verifiedAt = Date(verifiedAtEpochMs.toLong())
                }
                return VerifiedIdentity(
                    result.owner(),
                    result.verified(),
                    verifiedAt,
                    result.verificationMethod(),
                    result.canAttemptVerificationAgain(),
                    result.idScanUrl(),
                )
            }
            throw SudoIdentityVerificationException.FailedException("Mutation succeeded but output was null.")
        } catch (e: Throwable) {
            logger.warning("unexpected error $e")
            when (e) {
                is NotAuthorizedException -> throw SudoIdentityVerificationException.AuthenticationException(
                    cause = e,
                )
                is ApolloException -> throw SudoIdentityVerificationException.FailedException(cause = e)
                else -> throw interpretSudoIdentityVerificationException(e)
            }
        }
    }

    override fun reset() {
        this.logger.info("Resetting client.")
        this.graphQLClient.clearCaches()
    }

    private fun interpretSudoIdentityVerificationError(e: Error): SudoIdentityVerificationException {
        val error = e.customAttributes()[ERROR_TYPE]?.toString() ?: ""
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
        }
        return SudoIdentityVerificationException.FailedException(e.toString())
    }

    private fun interpretSudoIdentityVerificationException(e: Throwable): Throwable {
        return when (e) {
            is CancellationException,
            is SudoIdentityVerificationException,
            -> e
            else -> SudoIdentityVerificationException.UnknownException(e)
        }
    }
}
