/**
 * Copyright © 2020 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoidentityverification

import java.util.*

/**
 * Interface for generating universally unique identifiers (UUIDs).
 */
interface IdGenerator {

    /**
     * Generates an UUID.
     *
     * @return UUID.
     */
    fun generateId(): String

}

/**
 * Default ID generator implementation.
 */
class DefaultIdGenerator: IdGenerator {

    override fun generateId(): String {
        return UUID.randomUUID().toString().toUpperCase(Locale.ROOT)
    }

}