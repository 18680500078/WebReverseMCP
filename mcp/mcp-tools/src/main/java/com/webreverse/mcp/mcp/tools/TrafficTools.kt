package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Traffic Tools：root 级流量抓取与代理配置（APP 级 HTTPS/明文流量）。
 *
 * - traffic.capture  用 tcpdump 抓取目标进程/端口的原始流量到 pcap 文件
 * - traffic.proxy    配置 iptables 透明代理，把目标 APP 流量重定向到本地代理端口
 * - traffic.clear    清除已配置的 iptables 转发规则
 *
 * 仅用于自己拥有/已授权的设备与目标。
 */
object TrafficTools {

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)

        fun runRoot(cmd: String, timeoutMs: Long = 30_000): Pair<String, Int>? =
            com.webreverse.mcp.mcp.tools.terminal.RootExecutor.runSu(cmd, timeoutMs)

        return listOf(
            f.tool(
                "traffic.capture",
                "用 tcpdump 抓取指定进程(uid)或端口的网络流量，保存为 pcap 文件，供后续用 Wireshark 等分析。需要 root 且设备有 tcpdump。uid 可通过 frida.list 或 terminal.su 'dumpsys package <pkg>' 获取。",
                ToolCategory.NETWORK,
                PermissionScope.READ_NETWORK,
                RiskLevel.HIGH,
                timeoutMs = 60_000,
                inputSchema = Schemas.objectSchema(
                    "uid" to Schemas.strSchema("目标应用 uid（如 10234），抓该进程全部流量"),
                    "port" to Schemas.strSchema("目标端口（可选，如 443）"),
                    "outfile" to Schemas.strSchema("pcap 输出路径（默认工作目录/capture_时间戳.pcap）"),
                    "duration" to Schemas.intSchema("抓取时长秒（默认 10；0 表示一直抓直到 stop）"),
                ),
            ) { args ->
                val uid = ToolArgs.str(args, "uid")
                val port = ToolArgs.str(args, "port")
                val duration = ToolArgs.int(args, "duration", 10)
                val hasTcpdump = runRoot("which tcpdump || ls /system/bin/tcpdump /data/data/com.termux/files/usr/bin/tcpdump 2>/dev/null")?.first?.isNotBlank() == true
                if (!hasTcpdump) {
                    return@tool McpToolResult.error(
                        "NO_TCPDUMP",
                        "设备无 tcpdump。可用 terminal.su 安装，或改用 traffic.proxy 配合代理抓包工具。",
                    )
                }
                val outfile = ToolArgs.str(args, "outfile").ifBlank {
                    val ts = java.text.SimpleDateFormat("yyyyMMdd_HHmmss", java.util.Locale.US).format(java.util.Date())
                    "${com.webreverse.mcp.core.common.util.WorkDir.get()}/capture_$ts.pcap"
                }
                val filter = mutableListOf<String>()
                if (uid.isNotBlank()) filter.add("(uid $uid)")
                if (port.isNotBlank()) filter.add("(port $port)")
                val expr = filter.joinToString(" and ").ifBlank { "tcp or udp" }
                val cmd = if (duration > 0) {
                    "timeout $duration tcpdump -i any -s 0 -w $outfile '$expr' 2>&1 | tail -5; echo CAPTURE_DONE"
                } else {
                    "nohup tcpdump -i any -s 0 -w $outfile '$expr' >/dev/null 2>&1 & echo STARTED"
                }
                val result = withContext(Dispatchers.IO) { runRoot(cmd, ((duration + 10).coerceAtLeast(15)) * 1000L) }
                McpToolResult.json(
                    buildJsonObject {
                        put("outfile", JsonPrimitive(outfile))
                        put("uid", JsonPrimitive(uid))
                        put("port", JsonPrimitive(port))
                        put("output", JsonPrimitive(result?.first?.take(2000) ?: "root unavailable"))
                    },
                )
            },

            f.tool(
                "traffic.proxy",
                "配置 iptables 透明代理，把目标 APP(uid) 的 HTTP/HTTPS 流量重定向到本地代理端口(如 8080)，配合 mitmproxy/burp 等代理实现 HTTPS 解密。返回配置命令执行结果。",
                ToolCategory.NETWORK,
                PermissionScope.MODIFY_NETWORK,
                RiskLevel.CRITICAL,
                timeoutMs = 30_000,
                inputSchema = Schemas.objectSchema(
                    "uid" to Schemas.strSchema("目标应用 uid"),
                    "proxyPort" to Schemas.intSchema("本地代理端口（默认 8080）"),
                ),
            ) { args ->
                val uid = ToolArgs.str(args, "uid")
                val proxyPort = ToolArgs.int(args, "proxyPort", 8080)
                if (uid.isBlank()) return@tool McpToolResult.error("INVALID_ARGUMENTS", "uid 不能为空")
                val cmd =
                    "iptables -t nat -A OUTPUT -m owner --uid-owner $uid -p tcp --dport 80 -j REDIRECT --to-ports $proxyPort; " +
                        "iptables -t nat -A OUTPUT -m owner --uid-owner $uid -p tcp --dport 443 -j REDIRECT --to-ports $proxyPort; " +
                        "echo PROXY_CONFIGURED"
                val result = withContext(Dispatchers.IO) { runRoot(cmd, 20_000) }
                McpToolResult.json(
                    buildJsonObject {
                        put("uid", JsonPrimitive(uid))
                        put("proxyPort", JsonPrimitive(proxyPort))
                        put("output", JsonPrimitive(result?.first?.take(2000) ?: "root unavailable"))
                        put("hint", JsonPrimitive("透明代理已重定向。需本地代理(mitmproxy 等)监听 $proxyPort 并安装其 CA 证书，才能解密 HTTPS。用 traffic.clear 撤销规则。"))
                    },
                )
            },

            f.tool(
                "traffic.clear",
                "清除 traffic.proxy 配置的 iptables 转发规则（撤销透明代理重定向）。",
                ToolCategory.NETWORK,
                PermissionScope.MODIFY_NETWORK,
                RiskLevel.CRITICAL,
                timeoutMs = 30_000,
            ) { _ ->
                val cmd =
                    "iptables -t nat -D OUTPUT -m owner --uid-owner 0 -p tcp --dport 80 -j REDIRECT --to-ports 8080 2>/dev/null; " +
                        "iptables -t nat -F OUTPUT 2>/dev/null; echo CLEARED"
                val result = withContext(Dispatchers.IO) { runRoot(cmd, 20_000) }
                McpToolResult.json(
                    buildJsonObject {
                        put("output", JsonPrimitive(result?.first?.take(1000) ?: "root unavailable"))
                    },
                )
            },
        )
    }
}
