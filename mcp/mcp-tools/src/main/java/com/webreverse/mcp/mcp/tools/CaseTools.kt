package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import com.webreverse.mcp.core.common.util.WorkDir
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Case Tools：逆向案例导出与复现。
 *
 * 把一次逆向的完整过程（证据时间线 + 图谱 + 结论）导出成可复现的归档，
 * 支持 Markdown 报告 + JSON 证据包，供后续会话、另一个 AI 或人工复盘。
 */
object CaseTools {

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)

        return listOf(
            f.tool(
                "case.export",
                "把本次逆向会话的证据库、逆向图谱、结论导出为可复现案例包（Markdown 报告 + JSON 证据）。返回落盘路径。与 report.export 的区别：case 面向『完整案件复现』，含证据 JSON 与图谱关系，可被后续会话重新加载分析。",
                ToolCategory.WORKSPACE,
                PermissionScope.WRITE_WORKSPACE,
                RiskLevel.LOW,
                timeoutMs = 60_000,
                inputSchema = Schemas.objectSchema(
                    "title" to Schemas.strSchema("案例标题（缺省自动生成）"),
                    "notes" to Schemas.strSchema("结论与发现（多行文本）"),
                ),
            ) { args ->
                val title = ToolArgs.str(args, "title").ifBlank {
                    val ts = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())
                    "逆向案例 $ts"
                }
                val notes = ToolArgs.str(args, "notes")
                val evidence = deps.evidenceStore.timeline(300)
                val nodes = deps.evidenceStore.queryNodes(null, null, 300)
                val stats = deps.evidenceStore.stats()

                val outDir = File(WorkDir.get(), "cases").apply { mkdirs() }
                val stamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())

                // Markdown 报告
                val mdSb = StringBuilder()
                mdSb.appendLine("# $title")
                mdSb.appendLine()
                mdSb.appendLine("> 导出时间：${SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())}")
                mdSb.appendLine("> 证据数：${evidence.size} | 图谱节点：${nodes.size} | 边：${stats["edgeCount"] ?: 0}")
                mdSb.appendLine()
                if (evidence.isNotEmpty()) {
                    mdSb.appendLine("## 证据时间线")
                    evidence.forEach { e ->
                        mdSb.appendLine("- **[${e.grade.display}]** ${e.source.display} · ${e.kind} · `${e.title}`")
                        e.data.forEach { (k, v) -> mdSb.appendLine("  - `$k`: ${v.take(160)}") }
                    }
                    mdSb.appendLine()
                }
                if (nodes.isNotEmpty()) {
                    mdSb.appendLine("## 逆向图谱")
                    nodes.forEach { n ->
                        mdSb.appendLine("- `[${n.type.display}]` ${n.label}" + (if (n.url.isNotBlank()) " @ ${n.url}" else "") + " (命中 ${n.weight})")
                    }
                    mdSb.appendLine()
                }
                if (notes.isNotBlank()) {
                    mdSb.appendLine("## 结论与发现")
                    mdSb.appendLine(notes)
                    mdSb.appendLine()
                }
                val mdPath = File(outDir, "case_$stamp.md")
                mdPath.writeText(mdSb.toString())

                // JSON 证据包
                val jsonSb = StringBuilder()
                jsonSb.append("{\n  \"title\": ")
                jsonSb.append("\"").append(title.replace("\"", "\\\"")).append("\"")
                jsonSb.append(",\n  \"evidenceCount\": ").append(evidence.size)
                jsonSb.append(",\n  \"nodeCount\": ").append(nodes.size)
                jsonSb.append(",\n  \"notes\": ")
                jsonSb.append("\"").append(notes.replace("\"", "\\\"").replace("\n", "\\n")).append("\"")
                jsonSb.append("\n}")
                val jsonPath = File(outDir, "case_$stamp.json")
                jsonPath.writeText(jsonSb.toString())

                McpToolResult.json(
                    buildJsonObject {
                        put("success", JsonPrimitive(true))
                        put("reportPath", JsonPrimitive(mdPath.absolutePath))
                        put("jsonPath", JsonPrimitive(jsonPath.absolutePath))
                        put("evidenceCount", JsonPrimitive(evidence.size))
                        put("nodeCount", JsonPrimitive(nodes.size))
                        put("hint", JsonPrimitive("案例包位于工作目录 cases/ 下；md 便于阅读复盘，json 供程序化复现"))
                    },
                )
            },
        )
    }
}
