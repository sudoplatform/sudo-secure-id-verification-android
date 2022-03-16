/**
 * Copyright © 2020 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoidentityverification

import android.content.Context
import com.amazonaws.mobileconnectors.appsync.AWSAppSyncClient
import com.amazonaws.mobileconnectors.appsync.fetcher.AppSyncResponseFetchers
import com.apollographql.apollo.api.Error
import com.sudoplatform.sudoapiclient.ApiClientManager
import com.sudoplatform.sudoidentityverification.type.VerifyIdentityInput
import com.sudoplatform.sudoidentityverification.extensions.enqueue
import com.sudoplatform.sudoidentityverification.extensions.enqueueFirst
import com.apollographql.apollo.exception.ApolloException
import com.sudoplatform.sudologging.Logger
import com.sudoplatform.sudouser.SudoUserClient
import com.amazonaws.services.cognitoidentity.model.NotAuthorizedException
import java.util.Date
import java.util.concurrent.CancellationException

/**
 * Options for controlling the behaviour of query APIs.
 */
enum class QueryOption {
    /**
     * Returns result from the local cache only.
     */
    CACHE_ONLY,

    /**
     * Fetches result from the backend and ignores any cached entries.
     */
    REMOTE_ONLY
}

/**
 * Interface encapsulating a library of functions for identity verification.
 */
interface SudoIdentityVerificationClient {

    companion object {
        /**
         * Creates a [Builder] for [SudoIdentityVerificationClient].
         */
        fun builder(context: Context, sudoUserClient: SudoUserClient) =
            Builder(context, sudoUserClient)

    }

    /**
     * Builder used to construct [SudoIdentityVerificationClient].
     */
    class Builder(private val context: Context, private val sudoUserClient: SudoUserClient) {
        private var graphQLClient: AWSAppSyncClient? = null
        private var logger: Logger? = null

        /**
         * Provide an [AWSAppSyncClient] for the [SudoIdentityVerificationClient]. If this is not
         * supplied, an [AWSAppSyncClient] will be obtained from [ApiClientManager]. This is mainly
         * used for unit testing.
         */
        fun setGraphQLClient(graphQLClient: AWSAppSyncClient) = also {
            this.graphQLClient = graphQLClient
        }

        /**
         * Provide the implementation of the [Logger] used for logging. If a value is not supplied
         * a default implementation will be used.
         */
        fun setLogger(logger: Logger) = also {
            this.logger = logger
        }

        /**
         * Constructs and returns an [SudoIdentityVerificationClient].
         */
        fun build(): SudoIdentityVerificationClient {
            return DefaultSudoIdentityVerificationClient(
                this.context,
                this.sudoUserClient,
                this.logger ?: DefaultLogger.instance,
                this.graphQLClient ?: ApiClientManager.getClient(
                    this.context,
                    this.sudoUserClient
                )
            )
        }
    }

    /**
     * Checksum's for each file are generated and are used to create a checksum that is used when publishing to maven central.
     * In order to retry a failed publish without needing to change any functionality, we need a way to generate a different checksum
     * for the source code.  We can change the value of this property which will generate a different checksum for publishing
     * and allow us to retry.  The value of `version` doesn't need to be kept up-to-date with the version of the code.
     */
    val version: String

    /**
     * Retrieves the list of supported countries for identity verification.
     *
     * @return a list of supported countries.
     */
    @Throws(SudoIdentityVerificationException::class)
    suspend fun listSupportedCountries(): List<String>

    /**
     * Verifies an identity against the known public records and returns a result indicating whether or not the identity
     * details provided was verified with enough confidence to grant the user access to Sudo platform functions such
     * as provisioning a virtual card.
     *
     * @param firstName first name. Case insensitive.
     * @param lastName last name. Case insensitive.
     * @param address address. Case insensitive.
     * @param city city. Case insensitive.
     * @param state state. This is abbreviated name for the state, e.g. ‘NY’ not ‘New York’.
     * @param postalCode postal code.
     * @param country ISO 3166-1 alpha-2 country code. Must be one of countries retrieved via [listSupportedCountries] API.
     * @param dateOfBirth date of birth formatted in "yyyy-MM-dd".
     * @return verification result.
     */
    @Throws(SudoIdentityVerificationException::class)
    suspend fun verifyIdentity(
        firstName: String,
        lastName: String,
        address: String,
        city: String?,
        state: String?,
        postalCode: String,
        country: String,
        dateOfBirth: String
    ): VerifiedIdentity

    /**
     * Checks the identity verification status of the currently signed in user.
     *
     * @param option query option. See [QueryOption] enum.
     * @returns verification result.
     */
    @Throws(SudoIdentityVerificationException::class)
    suspend fun checkIdentityVerification(option: QueryOption): VerifiedIdentity

    /**
     * Reset any internal state and cached content.
     */
    fun reset()

}

/**
 * Default implementation of [SudoIdentityVerificationClient] interface.
 *
 * @param context Android app context.
 * @param sudoUserClient [SudoUserClient] instance required to issue authentication tokens and perform cryptographic operations.
 * @param logger logger used for logging messages.
 * @param graphQLClient optional GraphQL client to use. Mainly used for unit testing.
 */
class DefaultSudoIdentityVerificationClient(
    private val context: Context,
    private val sudoUserClient: SudoUserClient,
    private val logger: Logger = DefaultLogger.instance,
    graphQLClient: AWSAppSyncClient? = null
) : SudoIdentityVerificationClient {

    companion object {
        private const val VERIFICATION_METHOD = "KNOWLEDGE_OF_PII"

        /** Errors returned from the service */
        private const val ERROR_TYPE = "errorType"
        private const val SERVER_ERROR = "ServerError"
        private const val SERVICE_ERROR = "ServiceError"
        private const val ERROR_RECORD_NOT_FOUND = "IdentityVerificationRecordNotFoundError"
        private const val ERROR_UPDATE_FAILED = "IdentityVerificationUpdateFailedError"
        private const val ERROR_UNSUPPORTED_VERIFICATION_METHOD = "UnsupportedVerificationMethodError"
        private const val ERROR_IMPLAUSIBLE_AGE = "ImplausibleAgeError"
        private const val ERROR_INVALID_AGE = "InvalidAgeError"
        private const val ERROR_UNSUPPORTED_COUNTRY = "UnsupportedCountryError"
    }

    override val version: String = "5.1.1"

    /**
     * GraphQL client used for calling Sudo service API.
     */
    private val graphQLClient: AWSAppSyncClient

    init {
        @Suppress("UNCHECKED_CAST")
        this.graphQLClient = graphQLClient ?: ApiClientManager.getClient(
            context,
            this.sudoUserClient
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
                is NotAuthorizedException -> throw SudoIdentityVerificationException.AuthenticationException(cause = e)
                is ApolloException -> throw SudoIdentityVerificationException.FailedException(cause = e)
                else -> throw interpretSudoIdentityVerificationException(e)
            }
        }

    }

    override suspend fun verifyIdentity(
        firstName: String,
        lastName: String,
        address: String,
        city: String?,
        state: String?,
        postalCode: String,
        country: String,
        dateOfBirth: String
    ): VerifiedIdentity {
        this.logger.info("Verifying an identity.")

        if (!this.sudoUserClient.isSignedIn()) {
            throw SudoIdentityVerificationException.NotSignedInException()
        }

        try {
            val input = VerifyIdentityInput.builder()
                .verificationMethod(VERIFICATION_METHOD)
                .firstName(firstName)
                .lastName(lastName)
                .address(address)
                .city(city)
                .state(state)
                .postalCode(postalCode)
                .country(country)
                .dateOfBirth(dateOfBirth)
                .build()
            val mutation = VerifyIdentityMutation.builder()
                .input(input)
                .build()

            val response = this.graphQLClient.mutate(mutation)
                .enqueue()

            if (response.hasErrors()) {
                logger.warning("errors = ${response.errors()}")
                throw interpretSudoIdentityVerificationError(response.errors().first())
            }
            val output = response.data()?.verifyIdentity()
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
                    output.idScanUrl()
                )
            }
            throw SudoIdentityVerificationException.FailedException("Mutation succeeded but output was null.")
        } catch (e: Throwable) {
            logger.warning("unexpected error $e")
            when (e) {
                is NotAuthorizedException -> throw SudoIdentityVerificationException.AuthenticationException(cause = e)
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
                    output.idScanUrl()
                )
            }
            throw SudoIdentityVerificationException.FailedException("Query succeeded but output was null.")
        } catch (e: Throwable) {
            logger.warning("unexpected error $e")
            when (e) {
                is NotAuthorizedException -> throw SudoIdentityVerificationException.AuthenticationException(cause = e)
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
            return SudoIdentityVerificationException.IdentityVerificationRecordNotFoundException(message = error)
        } else if (error.contains(ERROR_UPDATE_FAILED)) {
            return SudoIdentityVerificationException.IdentityVerificationUpdateFailedException(message = error)
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
            is SudoIdentityVerificationException -> e
            else -> SudoIdentityVerificationException.UnknownException(e)
        }
    }
}