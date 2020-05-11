/**
 * Copyright © 2020 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoidentityverification

enum class ApiErrorCode {

    /**
     * Invalid configuration parameters were passed.
     */
    INVALID_CONFIG,

    /**
     * User is not authorized to perform the operation requested.
     */
    NOT_AUTHORIZED,

    /**
     * Client is not registered.
     */
    NOT_REGISTERED,

    /**
     * Client is not signed in.
     */
    NOT_SIGNED_IN,

    /**
     * Indicates the bad data was found in cache or in backend response.
     */
    BAD_DATA,

    /**
     * Indicates that the identity could not be verified.
     */
    IDENTITY_NOT_VERIFIED,

    /**
     * GraphQL endpoint returned an error.
     */
    GRAPHQL_ERROR,

    /**
     * Unexpected error encountered. This could be a result of client or backend bug and unlikely to be user
     * recoverable.
     */
    FATAL_ERROR

}

/**
 * [SudoIdentityVerificationClient] exception with a specific error code and message.
 *
 * @param code error code.
 * @param message error message.
 * @constructor Creates an API exception with the specified code and message.
 */
data class ApiException(val code: ApiErrorCode, override val message: String): Exception(message)
