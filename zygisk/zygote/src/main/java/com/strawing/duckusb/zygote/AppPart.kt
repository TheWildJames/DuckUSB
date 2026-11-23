package com.strawing.duckusb.zygote

import com.strawing.duckusb.common.Config
import com.strawing.duckusb.zygote.hook.Native
import com.strawing.duckusb.zygote.util.Logx
import com.strawing.duckusb.zygote.util.ModuleConfig
import com.strawing.duckusb.zygote.util.NativeLib

object AppPart {

    fun preSpecialize(packageName: String?) {
        if (packageName == Config.PKG) {
            runCatching { System.setProperty(Config.LIVE_PROPERTY, Config.MODULE_VERSION) }
            return
        }
        armAdbCover(packageName)
        armPropSpoof(packageName)
    }

    /**
     * The property layer claims init.svc.adbd=stopped, but /dev/socket/adbd and the abstract
     * @jdwp-control listener are kernel facts no property can mask. A detector that cross-checks
     * them reads a contradiction, which is worse than an honest "ADB enabled". Arm the libc
     * interposition for scoped apps whenever that claim is being made.
     */
    private fun armAdbCover(packageName: String?) {
        val config = ModuleConfig.config
        if (!ModuleConfig.active() || !config.spoofProps) return
        if (packageName == null) return
        if (config.targets.isNotEmpty() && packageName !in config.targets) return
        if (!config.coverAdbInode && !config.coverAdbListing && !config.coverAdbJdwp) return
        if (!NativeLib.load(ModuleConfig.moduleDir)) return

        val armed = runCatching {
            Native.installAdbCover(config.coverAdbInode, config.coverAdbListing, config.coverAdbJdwp)
        }.getOrElse {
            Logx.e("adb runtime cover failed to arm for $packageName", it)
            0
        }
        if (armed > 0) Logx.i("adb runtime cover armed for $packageName: $armed hooks")
    }

    private fun armPropSpoof(packageName: String?) {
        val config = ModuleConfig.config
        if (ModuleConfig.disabled || config.paused || !config.spoofUsbState) return

        val overrides = LinkedHashMap(Config.PROP_OVERRIDES)
        if (overrides.isEmpty()) return

        if (!NativeLib.load(ModuleConfig.moduleDir)) return

        val armed = runCatching {
            Native.installPropHooks(overrides.keys.toTypedArray(), overrides.values.toTypedArray())
        }.getOrElse {
            Logx.e("property spoof failed to arm for $packageName", it)
            0
        }
        if (armed > 0) Logx.i("property spoof armed for $packageName: $armed keys")
    }
}
