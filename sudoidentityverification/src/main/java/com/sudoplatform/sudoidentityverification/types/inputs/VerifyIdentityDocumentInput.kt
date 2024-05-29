/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoidentityverification.types.inputs

import com.sudoplatform.sudoidentityverification.types.IdDocumentType

/**
 * A request to verify an identity based on provided identity documents.
 *
 * @property imageBase64 [String] Base64 encoded image of front of government ID document.
 * @property backImageBase64 [String] Base64 encoded image of back of government ID document.
 * @property faceImageBase64 [String] Base64 encoded image of person's face.
 * @property country [String] ISO 3166-1 alpha-2 country code, e.g US.
 * @property documentType [IdDocumentType] Type of ID document being presented.
 */
data class VerifyIdentityDocumentInput(
    val imageBase64: String,
    val backImageBase64: String,
    val faceImageBase64: String? = null,
    val country: String,
    val documentType: IdDocumentType,
)
