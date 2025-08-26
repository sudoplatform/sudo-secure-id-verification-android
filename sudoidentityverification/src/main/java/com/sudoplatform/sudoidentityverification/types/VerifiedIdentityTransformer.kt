package com.sudoplatform.sudoidentityverification.types

import java.util.Date
import com.sudoplatform.sudoidentityverification.graphql.fragment.VerifiedIdentity as GraphQLVerifiedIdentity

internal object VerifiedIdentityTransformer {
    public fun toEntity(graphql: GraphQLVerifiedIdentity): VerifiedIdentity =
        VerifiedIdentity(
            owner = graphql.owner,
            verified = graphql.verified,
            verifiedAt = graphql.verifiedAtEpochMs.let { Date(it.toLong()) },
            verificationMethod = graphql.verificationMethod.toVerificationMethod(),
            canAttemptVerificationAgain = graphql.canAttemptVerificationAgain,
            idScanUrl = graphql.idScanUrl,
            requiredVerificationMethod = graphql.requiredVerificationMethod?.toVerificationMethod(),
            acceptableDocumentTypes = graphql.acceptableDocumentTypes.map { it.toIdDocumentType() },
            documentVerificationStatus = graphql.documentVerificationStatus.toDocumentVerificationStatus(),
            verificationLastAttemptedAt = graphql.verificationLastAttemptedAtEpochMs.let { Date(it.toLong()) },
            attemptsRemaining = graphql.attemptsRemaining,
        )
}

internal fun String.toVerificationMethod(): VerificationMethod {
    for (verificationMethod in VerificationMethod.entries) {
        if (verificationMethod.type == this) {
            return verificationMethod
        }
    }

    return VerificationMethod.UNKNOWN
}

internal fun String.toIdDocumentType(): IdDocumentType {
    for (idDocumentType in IdDocumentType.entries) {
        if (idDocumentType.type == this) {
            return idDocumentType
        }
    }

    return IdDocumentType.UNKNOWN
}

internal fun String.toDocumentVerificationStatus(): DocumentVerificationStatus {
    for (documentVerificationStatus in DocumentVerificationStatus.entries) {
        if (documentVerificationStatus.type == this) {
            return documentVerificationStatus
        }
    }

    return DocumentVerificationStatus.UNKNOWN
}
