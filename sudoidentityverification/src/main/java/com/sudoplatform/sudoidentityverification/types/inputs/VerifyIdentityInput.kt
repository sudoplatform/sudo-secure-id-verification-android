/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoidentityverification.types.inputs

/**
 * A request containing personally identifiable information required to verify an identity.
 *
 * @property firstName [String] First name. Case insensitive.
 * @property lastName [String] Last name. Case insensitive.
 * @property address [String] Address. Case insensitive.
 * @property city [String] City. Case insensitive.
 * @property state [String] State. This is abbreviated name for the state, e.g. ‘NY’ not ‘New York’.
 * @property postalCode [String] Postal code.
 * @property country [String] ISO 3166-1 alpha-2 country code. Must be one of countries retrieved via
 *  [SudoIdentityVerificationClient.listSupportedCountries] API.
 * @property dateOfBirth [String] Date of birth formatted in "yyyy-MM-dd".
 */
data class VerifyIdentityInput(
    val firstName: String,
    val lastName: String,
    val address: String,
    val city: String? = null,
    val state: String? = null,
    val postalCode: String,
    val country: String,
    val dateOfBirth: String,
)
