package com.webreverse.mcp.util

import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Root 检测与授权请求助手。
 *
 * Magisk 新版 su 无独立物理文件，且普通 app 进程 PATH 常不含 su，
 * 因此按已知路径逐个尝试执行 `su -c id`，以是否返回 uid=0 判定 root 可用。
 * 首次成功执行会弹出 Magisk 授权框，用户点「允许」后即完成授权。
 */
object RootHelper {

    /** 常见 su 路径（按优先级） */
    val SU_CANDIDATES = listOf(
        "/data/adb/magisk/busybox",
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/su/bin/su",
        "su",
    )

    const val DEFAULT_TIMEOUT_MS = 15_000L

    /** 执行一条 root 命令，返回 (输出, exitCode)；root 不可用返回 null */
    fun runSu(command: String, timeoutMs: Long = DEFAULT_TIMEOUT_MS): Pair<String, Int>? {
        for (suPath in SU_CANDIDATES) {
            val p = try {
                ProcessBuilder(suPath, "-c", command).redirectErrorStream(true).start()
            } catch (_: Exception) {
                continue
            }
            val out = StringBuilder()
            val t = Thread {
                try {
                    val r = p.inputStream.bufferedReader()
                    while (true) {
                        val line = r.readLine() ?: break
                        if (out.length < 64 * 1024) out.append(line).append('\n')
                    }
                } catch (_: Exception) {
                }
            }
            t.start()
            val done = p.waitFor(timeoutMs, TimeUnit.MILLISECONDS)
            if (!done) { p.destroyForcibly(); t.join(500); continue }
            t.join(500)
            return out.toString() to p.exitValue()
        }
        return null
    }

    /** 检测 root 是否可用（执行 id，看是否 uid=0） */
    fun isRootAvailable(timeoutMs: Long = DEFAULT_TIMEOUT_MS): Boolean {
        val result = runSu("id", timeoutMs) ?: return false
        return result.first.contains("uid=0")
    }

    /** 主动拉起一次 root 授权（会触发 Magisk 弹窗），返回是否成功 */
    fun requestRoot(timeoutMs: Long = DEFAULT_TIMEOUT_MS): Boolean {
        // 用 -c 'id' 触发授权；-v 或空闲命令也可，但 id 能同时验证
        return isRootAvailable(timeoutMs)
    }
}
