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
import com.sudoplatform.sudologging.Logger
import com.sudoplatform.sudouser.SudoUserClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers.IO
import kotlinx.coroutines.launch
import java.util.Date

/**
 * Result returned by API for verifying an identity. The API can fail with an
 * error or return the verified identity.
 */
sealed class VerificationResult {
    /**
     * Encapsulates a successful identity verification result.
     *
     * @param verifiedIdentity verified identity details.
     */
    data class Success(val verifiedIdentity: VerifiedIdentity) : VerificationResult()

    /**
     * Encapsulates a failed identity verification result.
     *
     * @param error [Throwable] encapsulating the error detail.
     */
    data class Failure(val error: Throwable) : VerificationResult()
}

/**
 * Result returned by API for retrieving the list of supported countries for
 * identity verification. The API can fail with an error or return the list of
 * supported countries..
 */
sealed class GetSupportedCountriesResult {
    /**
     * Encapsulates a successful supported countries retrieval result.
     *
     * @param countries list of support countries.
     */
    data class Success(val countries: List<String>) : GetSupportedCountriesResult()

    /**
     * Encapsulates a failed supported countries retrieval result.
     *
     * @param error [Throwable] encapsulating the error detail.
     */
    data class Failure(val error: Throwable) : GetSupportedCountriesResult()
}

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
     * Client version.
     */
    val version: String

    /**
     * Retrieves the list of supported countries for identity verification.
     *
     * @param callback callback for returning supported countries retrieval result or error.
     */
    @Deprecated(
        message = "This is deprecated and will be removed in the future.",
        replaceWith = ReplaceWith("getSupportedCountries()"),
        level = DeprecationLevel.WARNING
    )
    fun getSupportedCountries(callback: (GetSupportedCountriesResult) -> Unit)

    /**
     * Retrieves the list of supported countries for identity verification.
     *
     * @return a list of supported countries.
     */
    @Throws(SudoIdentityVerificationException::class)
    suspend fun getSupportedCountries(): List<String>

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
     * @param country ISO 3166-1 alpha-2 country code. Must be one of countries retrieved via [getSupportedCountries] API.
     * @param dateOfBirth date of birth formatted in "yyyy-MM-dd".
     * @param callback callback for returning verification result or error.
     */
    @Deprecated(
        message = "This is deprecated and will be removed in the future.",
        replaceWith = ReplaceWith("verifyIdentity(firstName, lastName, address, city, state, postalCode, country, dateOfBirth)"),
        level = DeprecationLevel.WARNING
    )
    fun verifyIdentity(
        firstName: String,
        lastName: String,
        address: String,
        city: String?,
        state: String?,
        postalCode: String,
        country: String,
        dateOfBirth: String,
        callback: (VerificationResult) -> Unit
    )

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
     * @param country ISO 3166-1 alpha-2 country code. Must be one of countries retrieved via [getSupportedCountries] API.
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
     * @param callback callback for returning verification result or error.
     */
    @Deprecated(
        message = "This is deprecated and will be removed in the future.",
        replaceWith = ReplaceWith("checkIdentityVerification(option)"),
        level = DeprecationLevel.WARNING
    )
    fun checkIdentityVerification(option: QueryOption, callback: (VerificationResult) -> Unit)

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

        private const val GRAPHQL_ERROR_TYPE = "errorType"
        private const val GRAPHQL_ERROR_SERVER_ERROR = "ServerError"
    }

    override val version: String = "2.0.3"

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

    override fun getSupportedCountries(callback: (GetSupportedCountriesResult) -> Unit) {
        CoroutineScope(IO).launch {
            try {
                val countries = this@DefaultSudoIdentityVerificationClient.getSupportedCountries()
                callback(GetSupportedCountriesResult.Success(countries))
            } catch (e: Throwable) {
                callback(
                    GetSupportedCountriesResult.Failure(
                        this@DefaultSudoIdentityVerificationClient.toApiException(
                            e
                        )
                    )
                )
            }
        }
    }

    override suspend fun getSupportedCountries(): List<String> {
        this.logger.info("Retrieving the list of supports countries for identity verification.")

        val response = this.graphQLClient.query(
            GetSupportedCountriesForIdentityVerificationQuery.builder().build()
        )
            .responseFetcher(AppSyncResponseFetchers.NETWORK_ONLY)
            .enqueue()

        if (!response.hasErrors()) {
            return response.data()?.supportedCountriesForIdentityVerification?.countryList()
                ?: listOf()
        } else {
            throw this.graphQLErrorToException(response.errors().first())
        }
    }

    override fun verifyIdentity(
        firstName: String,
        lastName: String,
        address: String,
        city: String?,
        state: String?,
        postalCode: String,
        country: String,
        dateOfBirth: String,
        callback: (VerificationResult) -> Unit
    ) {
        CoroutineScope(IO).launch {
            try {
                val verifiedIdentity = this@DefaultSudoIdentityVerificationClient.verifyIdentity(
                    firstName,
                    lastName,
                    address,
                    city,
                    state,
                    postalCode,
                    country,
                    dateOfBirth
                )
                callback(VerificationResult.Success(verifiedIdentity))
            } catch (e: Throwable) {
                callback(
                    VerificationResult.Failure(
                        this@DefaultSudoIdentityVerificationClient.toApiException(
                            e
                        )
                    )
                )
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
        val response = this.graphQLClient.mutate(
            VerifyIdentityMutation.builder().input(
                input
            ).build()
        ).enqueue()
        if (!response.hasErrors()) {
            val output = response.data()?.verifyIdentity()
            if (output != null) {
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
            } else {
                throw SudoIdentityVerificationException.FailedException("Mutation succeeded but output was null.")
            }
        } else {
            throw this.graphQLErrorToException(response.errors().first())
        }
    }

    override fun checkIdentityVerification(
        option: QueryOption,
        callback: (VerificationResult) -> Unit
    ) {
        CoroutineScope(IO).launch {
            try {
                val verifiedIdentity =
                    this@DefaultSudoIdentityVerificationClient.checkIdentityVerification(option)
                callback(VerificationResult.Success(verifiedIdentity))
            } catch (e: Throwable) {
                callback(
                    VerificationResult.Failure(
                        this@DefaultSudoIdentityVerificationClient.toApiException(
                            e
                        )
                    )
                )
            }
        }
    }

    override suspend fun checkIdentityVerification(option: QueryOption): VerifiedIdentity {
        this.logger.info("Checking the identity verification status.")

        val responseFetcher = when (option) {
            QueryOption.CACHE_ONLY -> {
                AppSyncResponseFetchers.CACHE_ONLY
            }
            QueryOption.REMOTE_ONLY -> {
                AppSyncResponseFetchers.NETWORK_ONLY
            }
        }

        val response = this.graphQLClient.query(CheckIdentityVerificationQuery.builder().build())
            .responseFetcher(responseFetcher)
            .enqueue()

        if (!response.hasErrors()) {
            val output = response.data()?.checkIdentityVerification()
            if (output != null) {
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
            } else {
                throw SudoIdentityVerificationException.FailedException("Mutation succeeded but output was null.")
            }
        } else {
            throw this.graphQLErrorToException(response.errors().first())
        }
    }

    override fun reset() {
        this.logger.info("Resetting client.")
        this.graphQLClient.clearCaches()
    }

    private fun graphQLErrorToException(error: Error): SudoIdentityVerificationException {
        this.logger.error("GraphQL error received: $error")

        return when (error.customAttributes()[GRAPHQL_ERROR_TYPE]) {
            GRAPHQL_ERROR_SERVER_ERROR -> {
                SudoIdentityVerificationException.InternalServerException(message = "$error")
            }
            else -> {
                SudoIdentityVerificationException.FailedException(message = "$error")
            }
        }
    }

    private fun toApiException(e: Throwable): ApiException {
        return when (e) {
            is SudoIdentityVerificationException.InternalServerException -> {
                ApiException(
                    ApiErrorCode.SERVER_ERROR,
                    e.message ?: "Internal server error occurred."
                )
            }
            else -> ApiException(
                ApiErrorCode.FATAL_ERROR,
                e.message ?: "Unexpected error occurred."
            )
        }
    }

}