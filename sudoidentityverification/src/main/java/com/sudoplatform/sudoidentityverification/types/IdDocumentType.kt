/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoidentityverification.types

/**
 * Type of document used for identity verification.
 */
enum class IdDocumentType(
    val type: String,
) {
    DRIVER_LICENSE("driverLicense"),
    PASSPORT("passport"),
    ID_CARD("idCard"),
    UNKNOWN("Unknown"),
}
