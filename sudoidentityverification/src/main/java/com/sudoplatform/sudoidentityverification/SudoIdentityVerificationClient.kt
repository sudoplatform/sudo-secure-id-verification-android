/**
 * Copyright © 2020 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoidentityverification

import android.content.Context
import com.amazonaws.mobileconnectors.appsync.AWSAppSyncClient
import com.amazonaws.mobileconnectors.appsync.fetcher.AppSyncResponseFetchers
import com.apollographql.apollo.GraphQLCall
import com.apollographql.apollo.api.Response
import com.apollographql.apollo.exception.ApolloException
import com.sudoplatform.sudoapiclient.ApiClientManager
import com.sudoplatform.sudoidentityverification.type.VerifyIdentityInput
import com.sudoplatform.sudologging.Logger
import com.sudoplatform.sudouser.SudoUserClient
import java.util.*

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

    /**
     * Client version.
     */
    val version: String

    /**
     * Retrieves the list of supported countries for identity verification.
     *
     * @param callback callback for returning supported countries retrieval result or error.
     */
    fun getSupportedCountries(callback: (GetSupportedCountriesResult) -> Unit)

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
     * Checks the identity verification status of the currently signed in user.
     *
     * @param option query option. See [QueryOption] enum.
     * @param callback callback for returning verification result or error.
     */
    fun checkIdentityVerification(option: QueryOption, callback: (VerificationResult) -> Unit)

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
 * @param idGenerator optional GUID generator to use. Mainly used for unit testing.
 */
class DefaultSudoIdentityVerificationClient(
    private val context: Context,
    private val sudoUserClient: SudoUserClient,
    private val logger: Logger = DefaultLogger.instance,
    graphQLClient: AWSAppSyncClient? = null,
    idGenerator: IdGenerator = DefaultIdGenerator()
) : SudoIdentityVerificationClient {

    companion object {
        private const val VERIFICATION_METHOD = "KNOWLEDGE_OF_PII"
    }

    override val version: String = "2.0.3"

    /**
     * GraphQL client used for calling Sudo service API.
     */
    private val graphQLClient: AWSAppSyncClient

    /**
     * UUID generator.
     */
    private val idGenerator: IdGenerator

    init {
        @Suppress("UNCHECKED_CAST")
        this.graphQLClient = graphQLClient ?: ApiClientManager.getClient(context,
            this.sudoUserClient
        )

        this.idGenerator = idGenerator
    }

    override fun getSupportedCountries(callback: (GetSupportedCountriesResult) -> Unit) {
        this.logger.info("Retrieving the list of supports countries for identity verification.")

        this.graphQLClient.query(GetSupportedCountriesForIdentityVerificationQuery.builder().build())
            .responseFetcher(AppSyncResponseFetchers.NETWORK_ONLY)
            .enqueue(object :
                GraphQLCall.Callback<GetSupportedCountriesForIdentityVerificationQuery.Data>() {
                override fun onResponse(response: Response<GetSupportedCountriesForIdentityVerificationQuery.Data>) {
                    val errors = response.errors()
                    if (errors.isEmpty()) {
                        // Iterate over Sudos.
                        val countries = response.data()
                            ?.supportedCountriesForIdentityVerification?.countryList()
                        callback(
                            GetSupportedCountriesResult.Success(countries ?: listOf())
                        )
                    } else {
                        callback(
                            GetSupportedCountriesResult.Failure(
                                ApiException(
                                    ApiErrorCode.GRAPHQL_ERROR,
                                    "$errors"
                                )
                            )
                        )
                    }
                }

                override fun onFailure(e: ApolloException) {
                    callback(
                        GetSupportedCountriesResult.Failure(e)
                    )
                }
            })
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
        this.graphQLClient.mutate(
            VerifyIdentityMutation.builder().input(
                input
            ).build()
        )
            .enqueue(object : GraphQLCall.Callback<VerifyIdentityMutation.Data>() {
                override fun onResponse(response: Response<VerifyIdentityMutation.Data>) {
                    val errors = response.errors()
                    if (errors.isEmpty()) {
                        val output = response.data()?.verifyIdentity()
                        if (output != null) {
                            var verifiedAt: Date? = null
                            val verifiedAtEpochMs = output.verifiedAtEpochMs()
                            if (verifiedAtEpochMs != null) {
                                verifiedAt = Date(verifiedAtEpochMs.toLong())
                            }

                            val verifiedIdentity = VerifiedIdentity(
                                output.owner(),
                                output.verified(),
                                verifiedAt,
                                output.verificationMethod(),
                                output.canAttemptVerificationAgain(),
                                output.idScanUrl()
                            )
                            callback(VerificationResult.Success(verifiedIdentity))
                        } else {
                            callback(
                                VerificationResult.Failure(
                                    IllegalStateException("Mutation succeeded but output was null.")
                                )
                            )
                        }
                    } else {
                        callback(
                            VerificationResult.Failure(
                                ApiException(
                                    ApiErrorCode.GRAPHQL_ERROR,
                                    "$errors"
                                )
                            )
                        )
                    }
                }

                override fun onFailure(e: ApolloException) {
                    callback(
                        VerificationResult.Failure(e)
                    )
                }
            })
    }

    override fun checkIdentityVerification(
        option: QueryOption,
        callback: (VerificationResult) -> Unit
    ) {
        this.logger.info("Checking the identity verification status.")

        val responseFetcher = when (option) {
            QueryOption.CACHE_ONLY -> {
                AppSyncResponseFetchers.CACHE_ONLY
            }
            QueryOption.REMOTE_ONLY -> {
                AppSyncResponseFetchers.NETWORK_ONLY
            }
        }

        this.graphQLClient.query(CheckIdentityVerificationQuery.builder().build())
            .responseFetcher(responseFetcher)
            .enqueue(object :
                GraphQLCall.Callback<CheckIdentityVerificationQuery.Data>() {
                override fun onResponse(response: Response<CheckIdentityVerificationQuery.Data>) {
                    val errors = response.errors()
                    if (errors.isEmpty()) {
                        val output = response.data()?.checkIdentityVerification()
                        if (output != null) {
                            var verifiedAt: Date? = null
                            val verifiedAtEpochMs = output.verifiedAtEpochMs()
                            if (verifiedAtEpochMs != null) {
                                verifiedAt = Date(verifiedAtEpochMs.toLong())
                            }

                            val verifiedIdentity = VerifiedIdentity(
                                output.owner(),
                                output.verified(),
                                verifiedAt,
                                output.verificationMethod(),
                                output.canAttemptVerificationAgain(),
                                output.idScanUrl()
                            )
                            callback(VerificationResult.Success(verifiedIdentity))
                        } else {
                            callback(
                                VerificationResult.Failure(
                                    IllegalStateException("Mutation succeeded but output was null.")
                                )
                            )
                        }
                    } else {
                        callback(
                            VerificationResult.Failure(
                                ApiException(
                                    ApiErrorCode.GRAPHQL_ERROR,
                                    "$errors"
                                )
                            )
                        )
                    }
                }

                override fun onFailure(e: ApolloException) {
                    callback(
                        VerificationResult.Failure(e)
                    )
                }
            })
    }

    override fun reset() {
        this.logger.info("Resetting client.")

        this.graphQLClient.clearCaches()
    }

}