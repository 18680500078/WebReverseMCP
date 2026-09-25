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
 * Report Export Tools：逆向成果数据闭环。
 *
 * 设计目标：逆向过程产生的证据、图谱、分析结论，不再只散落在 MCP 对话里，
 * 而能一键落盘为结构化的 Markdown 报告 + JSON 归档，供后续 AI 会话引用、
 * 人工复盘、或喂给其它工具二次分析。
 */
object ReportExportTools {

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)
        return listOf(
            f.tool(
                "report.export",
                "把本次逆向会话的证据库、逆向图谱、指定分析结论导出为结构化 Markdown 报告并落盘到工作目录。回传报告绝对路径与摘要，供后续会话 file.read 引用、人工复盘或喂给其它工具。",
                ToolCategory.REVERSE,
                PermissionScope.WRITE_FILE,
                RiskLevel.LOW,
                timeoutMs = 60_000,
                inputSchema = Schemas.objectSchema(
                    "title" to Schemas.strSchema("报告标题（缺省自动生成：WebReverse 逆向报告 <时间>）"),
                    "notes" to Schemas.strSchema("附加的分析结论/备注（多行文本，写入报告末尾的『结论与备注』小节）"),
                    "includeEvidence" to Schemas.boolSchema("是否包含证据时间线（默认 true）"),
                    "includeGraph" to Schemas.boolSchema("是否包含逆向图谱节点/边（默认 true）"),
                    "format" to Schemas.strSchema("导出格式：markdown（默认）/ json / both"),
                ),
            ) { args ->
                val title = ToolArgs.str(args, "title")
                val notes = ToolArgs.str(args, "notes")
                val includeEvidence = ToolArgs.bool(args, "includeEvidence", true)
                val includeGraph = ToolArgs.bool(args, "includeGraph", true)
                val format = ToolArgs.str(args, "format", "markdown")

                val reportTitle = title.ifBlank {
                    val ts = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())
                    "WebReverse 逆向报告 $ts"
                }

                val evidence = if (includeEvidence) deps.evidenceStore.timeline(200) else emptyList()
                val stats = deps.evidenceStore.stats()
                val nodes = if (includeGraph) deps.evidenceStore.queryNodes(null, null, 200) else emptyList()

                val outDir = File(WorkDir.get(), "reports").apply { mkdirs() }
                val stamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
                val mdPath = File(outDir, "report_$stamp.md")

                val sb = StringBuilder()
                sb.appendLine("# $reportTitle")
                sb.appendLine()
                sb.appendLine("> 导出时间：${SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())}")
                sb.appendLine("> 证据总数：${stats["evidenceCount"] ?: evidence.size}")
                sb.appendLine("> 图谱节点数：${nodes.size}")
                sb.appendLine()

                if (includeEvidence && evidence.isNotEmpty()) {
                    sb.appendLine("## 证据时间线")
                    sb.appendLine()
                    evidence.forEach { e ->
                        sb.appendLine("- **[${e.grade.display}]** ${e.source.display} · ${e.kind} · `${e.title}`")
                        e.data.forEach { (k, v) ->
                            val clipped = v.take(200)
                            sb.appendLine("  - `$k`: $clipped")
                        }
                    }
                    sb.appendLine()
                }

                if (includeGraph && nodes.isNotEmpty()) {
                    sb.appendLine("## 逆向图谱")
                    sb.appendLine()
                    nodes.forEach { n ->
                        sb.appendLine("- `[${n.type.display}]` ${n.label}" + if (n.url.isNotBlank()) " @ ${n.url}" else "" + " (命中 ${n.weight})")
                    }
                    sb.appendLine()
                }

                if (notes.isNotBlank()) {
                    sb.appendLine("## 结论与备注")
                    sb.appendLine()
                    sb.appendLine(notes)
                    sb.appendLine()
                }

                mdPath.writeText(sb.toString())

                var jsonPath: String? = null
                if (format == "json" || format == "both") {
                    jsonPath = File(outDir, "report_$stamp.json").absolutePath
                    val json = buildJsonObject {
                        put("title", JsonPrimitive(reportTitle))
                        put("evidenceCount", JsonPrimitive(evidence.size))
                        put("nodeCount", JsonPrimitive(nodes.size))
                        put("notes", JsonPrimitive(notes))
                    }.toString()
                    File(jsonPath).writeText(json)
                }

                McpToolResult.json(
                    buildJsonObject {
                        put("success", JsonPrimitive(true))
                        put("markdownPath", JsonPrimitive(mdPath.absolutePath))
                        if (jsonPath != null) put("jsonPath", JsonPrimitive(jsonPath))
                        put("evidenceCount", JsonPrimitive(evidence.size))
                        put("nodeCount", JsonPrimitive(nodes.size))
                        put("hint", JsonPrimitive("用 file.read 读取报告；报告目录位于工作目录 reports/ 下"))
                    },
                )
            },
        )
    }
}
