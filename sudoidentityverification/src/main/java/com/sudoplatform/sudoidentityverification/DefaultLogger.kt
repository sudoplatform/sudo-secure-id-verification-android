package com.sudoplatform.sudoidentityverification

import com.sudoplatform.sudologging.AndroidUtilsLogDriver
import com.sudoplatform.sudologging.LogLevel
import com.sudoplatform.sudologging.Logger

/**
 * Default logger.
 */
class DefaultLogger {

    companion object {
        val instance = Logger("SudoIdentityVerification", AndroidUtilsLogDriver(LogLevel.INFO))
    }

}