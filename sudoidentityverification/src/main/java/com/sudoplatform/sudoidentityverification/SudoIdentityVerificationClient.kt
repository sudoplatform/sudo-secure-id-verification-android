/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoidentityverification

import android.content.Context
import com.amazonaws.mobileconnectors.appsync.AWSAppSyncClient
import com.sudoplatform.sudoapiclient.ApiClientManager
import com.sudoplatform.sudoidentityverification.types.VerifiedIdentity
import com.sudoplatform.sudoidentityverification.types.inputs.VerifyIdentityDocumentInput
import com.sudoplatform.sudoidentityverification.types.inputs.VerifyIdentityInput
import com.sudoplatform.sudologging.Logger
import com.sudoplatform.sudouser.SudoUserClient

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
    REMOTE_ONLY,
}

/**
 * Interface encapsulating a library for interacting with the Sudo Platform Identity Verification service.
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
                    this.sudoUserClient,
                ),
            )
        }
    }

    /**
     * Checksums for each file are generated and are used to create a checksum that is used when publishing to maven central.
     * In order to retry a failed publish without needing to change any functionality, we need a way to generate a different checksum
     * for the source code.  We can change the value of this property which will generate a different checksum for publishing
     * and allow us to retry.  The value of `version` doesn't need to be kept up-to-date with the version of the code.
     */
    val version: String

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
     * Retrieves a flag indicating if face image must be submitted with identity
     * documents.
     *
     * @return boolean flag.
     *
     * @throws [SudoIdentityVerificationException].
     */
    @Throws(SudoIdentityVerificationException::class)
    suspend fun isFaceImageRequired(): Boolean

    /**
     * Checks the identity verification status of the currently signed in user.
     *
     * @param option [QueryOption] query option.
     * @returns A [VerifiedIdentity] verification result.
     *
     * @throws [SudoIdentityVerificationException].
     */
    @Throws(SudoIdentityVerificationException::class)
    suspend fun checkIdentityVerification(option: QueryOption): VerifiedIdentity

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
     * Reset any internal state and cached content.
     */
    fun reset()
}
