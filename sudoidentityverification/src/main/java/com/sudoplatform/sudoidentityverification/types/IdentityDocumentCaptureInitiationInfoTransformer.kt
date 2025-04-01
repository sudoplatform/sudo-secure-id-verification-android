package com.sudoplatform.sudoidentityverification.types

import java.util.Date
import com.sudoplatform.sudoidentityverification.graphql.InitiateIdentityDocumentCaptureMutation.InitiateIdentityDocumentCapture as GraphQLInitiateIdentityDocumentCapture

internal object IdentityDocumentCaptureInitiationInfoTransformer {
    public fun toEntity(graphql: GraphQLInitiateIdentityDocumentCapture): IdentityDocumentCaptureInitiationInfo {
        return IdentityDocumentCaptureInitiationInfo(
            documentCaptureUrl = graphql.documentCaptureUrl,
            expiryAt = Date(graphql.expiryAtEpochSeconds.toLong() * 1000L),
        )
    }
}
