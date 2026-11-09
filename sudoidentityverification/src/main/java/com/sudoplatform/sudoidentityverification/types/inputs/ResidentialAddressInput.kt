/*
 * Copyright © 2026 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoidentityverification.types.inputs

/**
 * The holder's residential address, supplied for a digital credential that carries none.
 *
 * @property address [String] Street address. Case insensitive.
 * @property city [String] City. Case insensitive.
 * @property state [String] State. This is abbreviated name for the state, e.g. ‘NY’ not ‘New York’.
 * @property postalCode [String] Postal code.
 * @property country [String] ISO 3166-1 alpha-2 country code. Must be one of countries retrieved via
 *  [SudoIdentityVerificationClient.listSupportedCountries] API.
 */
data class ResidentialAddressInput(
    val address: String,
    val city: String? = null,
    val state: String? = null,
    val postalCode: String,
    val country: String,
)
