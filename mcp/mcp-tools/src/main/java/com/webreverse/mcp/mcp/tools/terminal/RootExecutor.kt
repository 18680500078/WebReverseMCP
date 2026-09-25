package com.webreverse.mcp.mcp.tools.terminal

import java.util.concurrent.TimeUnit

/**
 * 受控 root 命令执行器。
 *
 * Magisk 新版 su 无独立物理文件，且普通 app 进程 PATH 常不含 su，
 * 因此按已知路径逐个尝试执行 `su -c`，全部失败返回 null（不降级，
 * 由调用方决定是否回退非 root sh）。
 *
 * 用于 terminal.su / frida.* 等需要 root 的高风险工具。
 */
object RootExecutor {

    val SU_CANDIDATES = listOf(
        "/data/adb/magisk/busybox",
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/su/bin/su",
        "su",
    )

    private const val MAX_OUTPUT = 256 * 1024

    /** 执行一条 root 命令，返回 (输出, exitCode)；root 不可用返回 null */
    fun runSu(command: String, timeoutMs: Long = 60_000): Pair<String, Int>? {
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
                        if (out.length < MAX_OUTPUT) out.append(line).append('\n')
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

    /** root 是否可用（执行 id 看是否 uid=0） */
    fun isRootAvailable(timeoutMs: Long = 15_000): Boolean {
        val r = runSu("id", timeoutMs) ?: return false
        return r.first.contains("uid=0")
    }
}
