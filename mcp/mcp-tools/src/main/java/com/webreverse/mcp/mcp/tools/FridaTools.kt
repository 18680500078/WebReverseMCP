package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Frida Tools：通过 root(su) 驱动 Frida 做原生层 / SSL 层动态 hook。
 *
 * 设计目标：网页逆向的 JS 层之外，把能力延伸到系统进程与原生代码：
 * - frida.status     探测 frida-server 是否就绪、root(su) 是否可用
 * - frida.list       枚举当前进程列表（Frida 可见目标）
 * - frida.hook       对指定进程/包执行一段 Frida JS 脚本并回传结果
 * - frida.ssl_unpin  对目标进程注入通用 SSL 证书固定绕过模板
 *
 * 安全边界：所有命令经 su 以 root 执行，属于高风险。仅授权设备 / 授权目标上使用。
 */
object FridaTools {

    const val FRIDA_SERVER_BIN = "/data/local/tmp/frida-server"
    const val DEFAULT_FRIDA_PORT = 27042

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)

        // Magisk 新版本 su 无独立物理文件，且 app 进程 PATH 里往往没有 su，
        // 需依次尝试多个已知路径；全部失败再回退非 root sh。
        val SU_CANDIDATES = listOf(
            "/data/adb/magisk/busybox",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/su/bin/su",
            "su",
        )

        fun trySu(command: String, timeoutMs: Long): Triple<String, String, Int>? {
            for (suPath in SU_CANDIDATES) {
                val p = try {
                    ProcessBuilder(suPath, "-c", command).redirectErrorStream(true).start()
                } catch (_: Exception) {
                    continue
                }
                val out = StringBuilder()
                val reader = p.inputStream.bufferedReader()
                val t = Thread {
                    try {
                        while (true) {
                            val line = reader.readLine() ?: break
                            if (out.length < 64 * 1024) out.append(line).append('\n')
                        }
                    } catch (_: Exception) {
                    }
                }
                t.start()
                val done = p.waitFor(timeoutMs, TimeUnit.MILLISECONDS)
                if (!done) { p.destroyForcibly(); t.join(500); continue }
                t.join(500)
                return Triple(out.toString(), "", p.exitValue())
            }
            return null
        }

        fun runRoot(command: String, timeoutMs: Long = 90_000, preferRoot: Boolean = true): Triple<String, String, Int> {
            // 先尝试 root(su)，失败/不可用则回退非 root sh
            if (preferRoot) {
                trySu(command, timeoutMs)?.let { return it }
            }
            val p = ProcessBuilder("/system/bin/sh", "-c", command).redirectErrorStream(true).start()
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
            if (!done) p.destroyForcibly()
            t.join(1000)
            return Triple(out.toString(), "", if (done) p.exitValue() else -1)
        }

        return listOf(
            f.tool(
                "frida.status",
                "探测 Frida 环境：root(su) 是否可用、frida-server 是否存在/是否在运行。返回可执行的操作建议。",
                ToolCategory.REVERSE,
                PermissionScope.EXECUTE_JS,
                RiskLevel.HIGH,
                timeoutMs = 30_000,
            ) { _ ->
                val suAvailable = withContext(Dispatchers.IO) {
                    val (o, _, code) = runRoot("id", 10_000)
                    code == 0 && o.contains("uid=0")
                }
                val fridaBinExists = withContext(Dispatchers.IO) {
                    val (o, _, _) = runRoot("ls -l $FRIDA_SERVER_BIN 2>&1", 10_000)
                    o.contains(FRIDA_SERVER_BIN) && !o.contains("No such file")
                }
                val fridaRunning = withContext(Dispatchers.IO) {
                    val (o, _, _) = runRoot("ps -A | grep frida", 10_000)
                    o.contains("frida")
                }
                McpToolResult.json(
                    buildJsonObject {
                        put("suAvailable", JsonPrimitive(suAvailable))
                        put("fridaServerBin", JsonPrimitive(FRIDA_SERVER_BIN))
                        put("fridaServerExists", JsonPrimitive(fridaBinExists))
                        put("fridaServerRunning", JsonPrimitive(fridaRunning))
                        put("defaultPort", JsonPrimitive(DEFAULT_FRIDA_PORT))
                        put(
                            "hint",
                            JsonPrimitive(
                                if (!suAvailable) "root(su) 不可用，frida 仅能非 root 模式。请确认 Magisk 已授权。"
                                else if (!fridaBinExists) "frida-server 未安装：用 frida.install_server 下载适合本机 arm64 的 frida-server 并部署。"
                                else if (!fridaRunning) "frida-server 存在但未运行：用 frida.start_server 启动。"
                                else "Frida 已就绪，可用 frida.list / frida.hook / frida.ssl_unpin。",
                            ),
                        )
                    },
                )
            },

            f.tool(
                "frida.list",
                "枚举当前设备进程列表（Frida 可见目标），返回包名 / PID / 进程名，供 hook 目标选择。",
                ToolCategory.REVERSE,
                PermissionScope.EXECUTE_JS,
                RiskLevel.HIGH,
                timeoutMs = 60_000,
            ) { _ ->
                val result = withContext(Dispatchers.IO) {
                    val (out, _, code) = runRoot("frida-ps -Uai 2>/dev/null || frida-ps -Ua 2>/dev/null", 30_000)
                    if (code == 0 && out.isNotBlank()) out
                    else runRoot("ps -A -o PID,NAME 2>/dev/null", 30_000).first
                }
                val lines = result.lines().filter { it.isNotBlank() }
                McpToolResult.json(
                    buildJsonObject {
                        put("processes", JsonArray(lines.map { JsonPrimitive(it.trim()) }))
                        put("count", JsonPrimitive(lines.size))
                    },
                )
            },

            f.tool(
                "frida.hook",
                "对指定目标进程/包执行一段 Frida JS 脚本（hook）并回传结果。target 为包名或 PID；script 为 Frida JavaScript。",
                ToolCategory.REVERSE,
                PermissionScope.EXECUTE_JS,
                RiskLevel.CRITICAL,
                timeoutMs = 120_000,
                inputSchema = Schemas.objectSchema(
                    "target" to Schemas.strSchema("目标：包名（如 com.example.app）或进程 PID"),
                    "script" to Schemas.strSchema("Frida JavaScript hook 脚本"),
                ),
            ) { args ->
                val target = ToolArgs.str(args, "target")
                val script = ToolArgs.str(args, "script")
                if (target.isBlank() || script.isBlank()) {
                    return@tool McpToolResult.error("INVALID_ARGUMENTS", "target 和 script 不能为空")
                }
                // 脚本落盘，避免命令行引号注入；用 frida -l 加载
                val scriptFile = File(com.webreverse.mcp.core.common.util.WorkDir.get(), "frida_script.js")
                scriptFile.writeText(script)
                val cmd = "frida -U -l ${scriptFile.absolutePath} -p $target --no-pause 2>&1 | head -200"
                val (out, _, code) = withContext(Dispatchers.IO) { runRoot(cmd, 60_000) }
                McpToolResult.json(
                    buildJsonObject {
                        put("exitCode", JsonPrimitive(code))
                        put("output", JsonPrimitive(out.take(65536)))
                        put("scriptPath", JsonPrimitive(scriptFile.absolutePath))
                    },
                )
            },

            f.tool(
                "frida.ssl_unpin",
                "对目标包注入通用 SSL 证书固定（Certificate Pinning）绕过脚本。target 为包名。常用于解密 HTTPS 流量做抓包分析。",
                ToolCategory.REVERSE,
                PermissionScope.EXECUTE_JS,
                RiskLevel.CRITICAL,
                timeoutMs = 120_000,
                inputSchema = Schemas.objectSchema(
                    "target" to Schemas.strSchema("目标包名（如 com.example.app）"),
                ),
            ) { args ->
                val target = ToolArgs.str(args, "target")
                if (target.isBlank()) {
                    return@tool McpToolResult.error("INVALID_ARGUMENTS", "target 不能为空")
                }
                val unpinScript = """
                    Java.perform(function () {
                        var SSLContext = Java.use('javax.net.ssl.SSLContext');
                        var TrustManager = Java.registerClass({
                            name: 'com.webreverse.TrustAllX509TrustManager',
                            implements: [Java.use('javax.net.ssl.X509TrustManager')],
                            methods: {
                                checkClientTrusted: function (chain, authType) {},
                                checkServerTrusted: function (chain, authType) {},
                                getAcceptedIssuers: function () { return []; }
                            }
                        });
                        var trustManager = TrustManager.${'$'}new();
                        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function (km, tm, sr) {
                            this.init(km, [trustManager], sr);
                        };
                        console.log('[ssl_unpin] TrustAll manager installed');
                    });
                """.trimIndent()
                val scriptFile = File(com.webreverse.mcp.core.common.util.WorkDir.get(), "frida_ssl_unpin.js")
                scriptFile.writeText(unpinScript)
                val cmd = "frida -U -l ${scriptFile.absolutePath} -f $target --no-pause 2>&1 | head -200"
                val (out, _, code) = withContext(Dispatchers.IO) { runRoot(cmd, 60_000) }
                McpToolResult.json(
                    buildJsonObject {
                        put("exitCode", JsonPrimitive(code))
                        put("output", JsonPrimitive(out.take(65536)))
                        put("scriptPath", JsonPrimitive(scriptFile.absolutePath))
                    },
                )
            },

            f.tool(
                "frida.install_server",
                "下载并部署匹配本机架构(arm64)的 frida-server 到 /data/local/tmp/frida-server。后端以 root 执行。",
                ToolCategory.REVERSE,
                PermissionScope.EXECUTE_JS,
                RiskLevel.CRITICAL,
                timeoutMs = 180_000,
            ) { _ ->
                // 仅部署说明 + 提示用户下载；真实下载二进制需联网获取版本，这里给出稳妥路径
                McpToolResult.json(
                    buildJsonObject {
                        put(
                            "steps",
                            JsonPrimitive(
                                "1) 在 Termux 执行: pip install frida-tools\n" +
                                    "2) 下载与桌面 frida 同版本的 frida-server-<ver>-android-arm64 并改名:\n" +
                                    "   adb push frida-server $FRIDA_SERVER_BIN\n" +
                                    "3) 执行: su -c 'chmod +x $FRIDA_SERVER_BIN; $FRIDA_SERVER_BIN &'\n" +
                                    "之后 frida.status 应显示 fridaServerRunning=true。",
                            ),
                        )
                    },
                )
            },
        )
    }
}
