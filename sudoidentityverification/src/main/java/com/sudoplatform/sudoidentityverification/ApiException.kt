/**
 * Copyright © 2020 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoidentityverification

enum class ApiErrorCode {

    /**
     * An internal server error cause the API call to fail. The error is
     * possibly transient and retrying at a later time may cause the call
     * to complete successfully.
     */
    SERVER_ERROR,

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
