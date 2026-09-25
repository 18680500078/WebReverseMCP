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

        // 复用受控 root 执行器（terminal 包），root 命令统一走 RootExecutor.runSu
        fun runRoot(command: String, timeoutMs: Long = 90_000): Triple<String, String, Int> {
            val r = com.webreverse.mcp.mcp.tools.terminal.RootExecutor.runSu(command, timeoutMs)
            return if (r != null) Triple(r.first, "", r.second)
            else Triple("", "root unavailable", -1)
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
                                else if (!fridaBinExists) "frida-server 未安装：用 file 上传 frida-server arm64 二进制到 /data/local/tmp/frida-server，或用 frida.install_server 查看部署步骤。"
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
                "frida.start_server",
                "以 root 启动 frida-server（默认监听 127.0.0.1:27042）。会先 chmod +x 再后台启动，返回启动结果。frida-server 需已存在于 /data/local/tmp/frida-server（可用 upload 工具或 frida.status 检查）。启动后外部 frida 客户端可直接连本机 frida-server。",
                ToolCategory.REVERSE,
                PermissionScope.EXECUTE_JS,
                RiskLevel.CRITICAL,
                timeoutMs = 60_000,
                inputSchema = Schemas.objectSchema(
                    "listen" to Schemas.strSchema("监听地址（默认 127.0.0.1:27042）"),
                ),
            ) { args ->
                val listen = ToolArgs.str(args, "listen", "127.0.0.1:27042")
                val cmd = "chmod 755 $FRIDA_SERVER_BIN && nohup $FRIDA_SERVER_BIN -l $listen >/dev/null 2>&1 & echo STARTED"
                val result = withContext(Dispatchers.IO) {
                    com.webreverse.mcp.mcp.tools.terminal.RootExecutor.runSu(cmd, 30_000)
                }
                if (result == null) {
                    return@tool McpToolResult.error("ROOT_UNAVAILABLE", "root 不可用，无法启动 frida-server")
                }
                // 二次确认是否真跑起来了
                val check = withContext(Dispatchers.IO) {
                    com.webreverse.mcp.mcp.tools.terminal.RootExecutor.runSu("ps -A | grep frida", 10_000)
                }
                val running = check?.first?.contains("frida") == true
                McpToolResult.json(
                    buildJsonObject {
                        put("started", JsonPrimitive(result.first.contains("STARTED")))
                        put("running", JsonPrimitive(running))
                        put("listen", JsonPrimitive(listen))
                        put("output", JsonPrimitive(result.first.take(2000)))
                    },
                )
            },

            f.tool(
                "frida.stop_server",
                "停止 frida-server 进程（以 root 执行 pkill frida-server）。",
                ToolCategory.REVERSE,
                PermissionScope.EXECUTE_JS,
                RiskLevel.CRITICAL,
                timeoutMs = 30_000,
            ) { _ ->
                val result = withContext(Dispatchers.IO) {
                    com.webreverse.mcp.mcp.tools.terminal.RootExecutor.runSu("pkill -f frida-server 2>/dev/null; echo DONE", 15_000)
                }
                McpToolResult.json(
                    buildJsonObject {
                        put("stopped", JsonPrimitive(result?.first?.contains("DONE") == true))
                        put("output", JsonPrimitive(result?.first?.take(1000) ?: "root unavailable"))
                    },
                )
            },

            f.tool(
                "frida.install_server",
                "部署说明 + 启动引导：frida-server 二进制需先上传到 /data/local/tmp/frida-server（可用本系统 file 上传或外部工具），然后用 frida.start_server 启动。本工具返回清晰步骤。",
                ToolCategory.REVERSE,
                PermissionScope.EXECUTE_JS,
                RiskLevel.CRITICAL,
                timeoutMs = 30_000,
            ) { _ ->
                McpToolResult.json(
                    buildJsonObject {
                        put(
                            "steps",
                            JsonPrimitive(
                                "1) 上传 frida-server（arm64）二进制到 $FRIDA_SERVER_BIN\n" +
                                    "2) 调用 frida.start_server 启动（会自动 chmod +x 并后台运行，监听 127.0.0.1:27042）\n" +
                                    "3) frida.status 确认 fridaServerRunning=true\n" +
                                    "4) 外部 frida 客户端（电脑 frida-tools）用 frida -H <手机IP>:27042 连接；\n" +
                                    "   或本机 terminal.su 直接执行 root 命令配合 hook。",
                            ),
                        )
                    },
                )
            },
        )
    }
}
