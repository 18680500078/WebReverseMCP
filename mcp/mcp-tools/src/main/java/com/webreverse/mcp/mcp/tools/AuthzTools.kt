package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.model.NetworkEntry
import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets

/**
 * 越权 / IDOR 矩阵引擎（authz.*）。
 *
 * 核心思想：把「资源（请求）× 身份（凭证）」做笛卡尔积重放，
 * 再按「响应状态 + 响应体相似度」自动判定越权，而不是只看状态码差异。
 *
 * 与 fuzz.replay 的区别：
 * - fuzz.replay 用「原请求自带的凭证」换参数值（单身份）
 * - authz.matrix 用「任意身份」×「任意资源」，并跨身份比对响应体（这才是矩阵）
 *
 * 传输层：java.net.HttpURLConnection（非页面 fetch），
 * 因此不受同源策略 / CORS 限制，且可任意设置 Cookie / Authorization 等请求头。
 *
 * 仅用于自己拥有或已获授权的目标。
 */
object AuthzTools {

    private const val BODY_LIMIT = 256 * 1024
    private const val PREVIEW_LEN = 1500
    private const val DEFAULT_SIM_THRESHOLD = 0.80
    private const val SIM_MAX_CHARS = 20_000

    // ---------------------------------------------------------------- 数据模型

    private data class Identity(
        val name: String,
        val headers: Map<String, String>,
        val anonymous: Boolean = false,
    )

    private data class Target(
        val name: String,
        val url: String,
        val method: String,
        val headers: Map<String, String>,
        val body: String?,
    )

    private data class Row(
        val target: Target,
        val value: String,
        val url: String,
        val body: String?,
    )

    private data class HttpResult(
        val ok: Boolean,
        val status: Int,
        val body: String,
        val error: String?,
        val elapsedMs: Long,
    )

    private data class Cell(
        val targetName: String,
        val originUrl: String,
        val value: String,
        val displayUrl: String,
        val identity: String,
        val status: Int,
        val length: Int,
        val body: String,
        val error: String?,
        val elapsedMs: Long,
    )

    private data class Finding(
        val severity: String,
        val type: String,
        val target: String,
        val value: String,
        val identity: String,
        val detail: String,
    )

    // ---------------------------------------------------------------- 工具注册

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)

        return listOf(
            f.tool(
                name = "authz.matrix",
                description = "越权/IDOR 矩阵引擎：对「N 个请求(资源) × M 个身份(凭证)」做交叉重放，" +
                    "并按【响应状态 + 响应体相似度】自动判定越权，输出矩阵明细 + 漏洞发现(findings)。\n" +
                    "典型发现：UNAUTHORIZED_ACCESS(匿名也能访问) / HORIZONTAL_IDOR(换身份读到同一份数据) / " +
                    "PARAM_IDOR(改 ID 后仍读到他人数据) / CROSS_IDENTITY_DIFFERENT_BODY(需人工确认) / PROTECTED(鉴权正常)。\n" +
                    "传输走原生 HttpURLConnection，不受 CORS 限制，可任意设置 Cookie/Authorization 头。\n" +
                    "identities 两种写法：① JSON 数组 [{\"name\":\"A\",\"headers\":{\"Authorization\":\"Bearer x\"}}]；" +
                    "② 简写 A=<entryId>,B=<entryId>（从已捕获请求提取该请求全部请求头作为该身份）。\n" +
                    "仅用于自己拥有或已获授权的目标。",
                category = ToolCategory.NETWORK,
                permission = PermissionScope.MODIFY_NETWORK,
                riskLevel = RiskLevel.HIGH,
                timeoutMs = 300_000,
                inputSchema = Schemas.objectSchema(
                    "identities" to Schemas.strSchema(
                        "身份列表（必填）。JSON 数组，或简写 A=<entryId>,B=<entryId>",
                    ),
                    "requests" to Schemas.strSchema(
                        "目标请求 JSON 数组：[{\"name\":\"用户详情\",\"url\":\"https://host/user/1001\"," +
                            "\"method\":\"GET\",\"headers\":{},\"body\":null}]",
                    ),
                    "entries" to Schemas.strSchema(
                        "逗号分隔的已捕获请求 ID（network.list 的 id），以其 url/method/headers/body 作为目标",
                    ),
                    "targetParams" to Schemas.strSchema(
                        "要替换的参数名，逗号分隔（如 id,uid,orderId）。留空则只测原始请求",
                    ),
                    "values" to Schemas.strSchema(
                        "参数候选值，逗号分隔（如 1001,1002）。留空则只测原始值",
                    ),
                    "baseline" to Schemas.strSchema("基准身份名（默认取第一个身份），用于跨身份比对"),
                    "anonymous" to Schemas.strSchema("是否追加「无凭证」身份 true/false（默认 false）"),
                    "threshold" to Schemas.strSchema("判定为同一对象的相似度阈值 0~1（默认 0.80）"),
                    "maxCells" to Schemas.strSchema("最大重放次数上限（默认 80，防误操作打爆目标）"),
                    "perRequestTimeoutMs" to Schemas.strSchema("单次请求超时毫秒（默认 15000）"),
                    "includeBodyPreview" to Schemas.strSchema("是否返回响应体片段 true/false（默认 true）"),
                    required = listOf("identities"),
                ),
                block = { args -> runMatrix(deps, args) },
            ),
        )
    }

    // ---------------------------------------------------------------- 主流程

    private suspend fun runMatrix(deps: ToolDependencies, args: JsonObject): McpToolResult {
        val identitiesRaw = ToolArgs.str(args, "identities").trim()
        if (identitiesRaw.isBlank()) {
            return McpToolResult.error(
                "INVALID_ARGUMENTS",
                "identities 不能为空。示例：A=<entryId>,B=<entryId> 或 [{\"name\":\"A\",\"headers\":{\"Authorization\":\"Bearer x\"}}]",
            )
        }
        val entriesRaw = ToolArgs.str(args, "entries").trim()
        val requestsRaw = ToolArgs.str(args, "requests").trim()
        if (entriesRaw.isBlank() && requestsRaw.isBlank()) {
            return McpToolResult.error("INVALID_ARGUMENTS", "requests 与 entries 至少要提供一个，否则没有可测目标")
        }

        val targetParams = splitCsv(ToolArgs.str(args, "targetParams"))
        val values = splitCsv(ToolArgs.str(args, "values"))
        val baselineName = ToolArgs.str(args, "baseline").trim()
        val anonymous = ToolArgs.bool(args, "anonymous", false)
        val threshold = ToolArgs.str(args, "threshold").trim().toDoubleOrNull()?.coerceIn(0.0, 1.0)
            ?: DEFAULT_SIM_THRESHOLD
        val maxCells = ToolArgs.str(args, "maxCells").trim().toIntOrNull()?.coerceIn(1, 1000) ?: 80
        val perTimeout = ToolArgs.str(args, "perRequestTimeoutMs").trim().toIntOrNull()
            ?.coerceIn(1000, 120_000) ?: 15_000
        val includePreview = ToolArgs.bool(args, "includeBodyPreview", true)

        val session = deps.activeSession()
        val captured: List<NetworkEntry> = try {
            deps.networkInspector.getEntries(session.engine)
        } catch (_: Exception) {
            emptyList()
        }

        // ---- 1) 身份
        val identities = parseIdentities(identitiesRaw, captured)
        if (identities.isEmpty()) {
            return McpToolResult.error(
                "INVALID_IDENTITIES",
                "没能解析出身份。JSON 写法请检查格式；简写 A=<entryId> 请确认 entryId 来自 network.list 且已捕获。",
            )
        }

        // ---- 2) 目标
        val targets = mutableListOf<Target>()
        targets += parseRequests(requestsRaw)
        if (entriesRaw.isNotBlank()) {
            entriesRaw.split(',').map { it.trim() }.filter { it.isNotBlank() }.forEach { id ->
                captured.firstOrNull { it.id == id }?.let { e ->
                    targets += Target(
                        name = e.method.wire + " " + shortPath(e.url),
                        url = e.url,
                        method = e.method.wire,
                        headers = e.requestHeaders,
                        body = e.requestBody,
                    )
                }
            }
        }
        if (targets.isEmpty()) {
            return McpToolResult.error(
                "NO_TARGETS",
                "没能解析出目标。请检查 requests 的 JSON 格式，或确认 entries 的 ID 来自 network.list（可先用 network.list 查看 id）。",
            )
        }

        // ---- 3) 展开成行（目标 × 参数值）
        val rows = mutableListOf<Row>()
        for (t in targets) {
            if (targetParams.isEmpty() || values.isEmpty()) {
                rows += Row(t, "", t.url, t.body)
            } else {
                for (v in values) {
                    var u = t.url
                    for (p in targetParams) u = substituteQuery(u, p, v)
                    val rawBody = t.body
                    val srcBody: String = rawBody ?: ""
                    val b: String? = if (rawBody == null) {
                        null
                    } else {
                        var tmp: String = srcBody
                        for (p in targetParams) tmp = substituteBody(tmp, p, v)
                        tmp
                    }
                    rows += Row(t, v, u, b)
                }
            }
        }

        // ---- 4) 身份全集（含可选匿名）
        val allIdentities = mutableListOf<Identity>()
        allIdentities += identities
        if (anonymous) {
            allIdentities += Identity(name = identities.first().name + "@anon", headers = emptyMap(), anonymous = true)
        }
        val baseline = allIdentities.firstOrNull { it.name == baselineName } ?: allIdentities.first()

        // ---- 5) 单元格上限保护
        val planned = rows.size * allIdentities.size
        if (planned > maxCells) {
            return McpToolResult.error(
                "TOO_MANY_CELLS",
                "本次将发起 $planned 次重放，超过 maxCells=$maxCells 上限。请减少 targets/values，或调高 maxCells（谨慎）。",
            )
        }

        // ---- 6) 执行矩阵
        val cells = mutableListOf<Cell>()
        for (row in rows) {
            val rowCells = coroutineScope {
                allIdentities.map { idn ->
                    async { executeCell(row, idn, perTimeout) }
                }.awaitAll()
            }
            cells += rowCells
        }

        // ---- 7) 分析
        val findings = analyze(cells, baseline.name, threshold)

        // ---- 8) 组装输出
        val byRow = cells.groupBy { it.targetName to it.value }

        val matrixJson = JsonArray(
            byRow.entries.map { (rowKey, rowCells) ->
                val base = rowCells.firstOrNull { it.identity == baseline.name }
                buildJsonObject {
                    put("target", JsonPrimitive(rowKey.first))
                    put("value", JsonPrimitive(rowKey.second))
                    put("url", JsonPrimitive(rowCells.firstOrNull()?.displayUrl ?: ""))
                    put(
                        "cells",
                        JsonArray(
                            rowCells.map { c ->
                                val sim = if (base == null || base === c) 1.0 else similarity(base.body, c.body)
                                buildJsonObject {
                                    put("identity", JsonPrimitive(c.identity))
                                    put("status", JsonPrimitive(c.status))
                                    put("length", JsonPrimitive(c.length))
                                    put("similarityToBaseline", JsonPrimitive(round2(sim)))
                                    put("ms", JsonPrimitive(c.elapsedMs))
                                    if (c.error != null) put("error", JsonPrimitive(c.error))
                                    if (includePreview) {
                                        put("preview", JsonPrimitive(truncate(compact(c.body), PREVIEW_LEN)))
                                    }
                                }
                            },
                        ),
                    )
                }
            },
        )

        val findingsJson = JsonArray(
            findings.map { fnd ->
                buildJsonObject {
                    put("severity", JsonPrimitive(fnd.severity))
                    put("type", JsonPrimitive(fnd.type))
                    put("target", JsonPrimitive(fnd.target))
                    put("value", JsonPrimitive(fnd.value))
                    put("identity", JsonPrimitive(fnd.identity))
                    put("detail", JsonPrimitive(fnd.detail))
                }
            },
        )

        val identityNames = JsonArray(allIdentities.map { JsonPrimitive(it.name) })

        return McpToolResult.json(
            buildJsonObject {
                put(
                    "summary",
                    buildJsonObject {
                        put("targets", JsonPrimitive(targets.size))
                        put("rows", JsonPrimitive(rows.size))
                        put("identities", identityNames)
                        put("baseline", JsonPrimitive(baseline.name))
                        put("cellsExecuted", JsonPrimitive(cells.size))
                        put("findingsHigh", JsonPrimitive(findings.count { it.severity == "HIGH" }))
                        put("findingsMedium", JsonPrimitive(findings.count { it.severity == "MEDIUM" }))
                        put("similarityThreshold", JsonPrimitive(threshold))
                        put("transport", JsonPrimitive("HttpURLConnection(no-CORS)"))
                    },
                )
                put("matrix", matrixJson)
                put("findings", findingsJson)
                put(
                    "legend",
                    buildJsonObject {
                        put("UNAUTHORIZED_ACCESS", JsonPrimitive("匿名(无凭证)也拿到 2xx —— 接口未鉴权"))
                        put(
                            "HORIZONTAL_IDOR",
                            JsonPrimitive("非基准身份拿到 2xx 且响应体与基准高度相似 —— 同一对象被跨身份读取（水平越权）"),
                        )
                        put(
                            "CROSS_IDENTITY_DIFFERENT_BODY",
                            JsonPrimitive("非基准身份拿到 2xx 但响应体不同 —— 可能各自数据，也可能读到他人数据，需人工确认"),
                        )
                        put(
                            "PARAM_IDOR",
                            JsonPrimitive("基准身份改用「非原始」参数值仍拿到 2xx —— 可直接改 ID 读他人对象"),
                        )
                        put("PROTECTED", JsonPrimitive("非基准身份被 401/403 拒绝 —— 鉴权正常"))
                    },
                )
            },
        )
    }

    // ---------------------------------------------------------------- 单元格执行

    private suspend fun executeCell(row: Row, idn: Identity, timeoutMs: Int): Cell {
        val merged = LinkedHashMap<String, String>()
        row.target.headers.forEach { (k, v) ->
            if (k.isNotBlank() && !isForbiddenHeader(k)) merged[k] = v
        }
        if (idn.anonymous) {
            merged.keys.toList().filter { isAuthHeader(it) }.forEach { merged.remove(it) }
        } else {
            idn.headers.forEach { (k, v) ->
                if (k.isNotBlank() && !isForbiddenHeader(k)) merged[k] = v
            }
        }
        val res = httpCall(row.url, row.target.method, merged, row.body, timeoutMs)
        return Cell(
            targetName = row.target.name,
            originUrl = row.target.url,
            value = row.value,
            displayUrl = redactUrl(row.url),
            identity = idn.name,
            status = res.status,
            length = res.body.length,
            body = res.body,
            error = res.error,
            elapsedMs = res.elapsedMs,
        )
    }

    // ---------------------------------------------------------------- 解析

    private fun parseIdentities(raw: String, captured: List<NetworkEntry>): List<Identity> {
        val trimmed = raw.trim()
        if (trimmed.startsWith("[")) {
            val arr = try {
                kotlinx.serialization.json.Json.parseToJsonElement(trimmed) as? JsonArray
            } catch (_: Exception) {
                null
            } ?: return emptyList()

            val out = mutableListOf<Identity>()
            arr.forEach { el ->
                val obj = el as? JsonObject ?: return@forEach
                val name = (obj["name"] as? JsonPrimitive)?.content ?: ("id" + (out.size + 1))
                val hs: Map<String, String> = (obj["headers"] as? JsonObject)?.let { h ->
                    h.entries.mapNotNull { (k, v) ->
                        val s = (v as? JsonPrimitive)?.content ?: return@mapNotNull null
                        k to s
                    }.toMap()
                } ?: emptyMap()
                out += Identity(name = name, headers = hs)
            }
            return out
        }

        val out = mutableListOf<Identity>()
        trimmed.split(',').forEach { part ->
            val seg = part.trim()
            if (seg.isBlank()) return@forEach
            val idx = seg.indexOf('=')
            if (idx <= 0) return@forEach
            val name = seg.substring(0, idx).trim()
            val entryId = seg.substring(idx + 1).trim()
            val entry = captured.firstOrNull { it.requestId == entryId || it.id == entryId }
            if (entry != null) {
                out += Identity(name = name, headers = entry.requestHeaders)
            }
        }
        return out
    }

    private fun parseRequests(raw: String): List<Target> {
        if (raw.isBlank()) return emptyList()
        val arr = try {
            kotlinx.serialization.json.Json.parseToJsonElement(raw.trim()) as? JsonArray
        } catch (_: Exception) {
            null
        } ?: return emptyList()

        val out = mutableListOf<Target>()
        arr.forEach { el ->
            val obj = el as? JsonObject ?: return@forEach
            val url = (obj["url"] as? JsonPrimitive)?.content ?: return@forEach
            val method = (obj["method"] as? JsonPrimitive)?.content?.takeIf { it.isNotBlank() } ?: "GET"
            val name = (obj["name"] as? JsonPrimitive)?.content?.takeIf { it.isNotBlank() }
                ?: (method + " " + shortPath(url))
            val headers: Map<String, String> = (obj["headers"] as? JsonObject)?.let { h ->
                h.entries.mapNotNull { (k, v) ->
                    val s = (v as? JsonPrimitive)?.content ?: return@mapNotNull null
                    k to s
                }.toMap()
            } ?: emptyMap()
            val body = (obj["body"] as? JsonPrimitive)?.content
            out += Target(name = name, url = url, method = method, headers = headers, body = body)
        }
        return out
    }

    // ---------------------------------------------------------------- 分析

    private fun analyze(cells: List<Cell>, baselineName: String, threshold: Double): List<Finding> {
        val out = mutableListOf<Finding>()
        val rows = cells.groupBy { it.targetName to it.value }

        for ((rowKey, rowCells) in rows) {
            val tName = rowKey.first
            val value = rowKey.second
            val base = rowCells.firstOrNull { it.identity == baselineName }
            val baseOk = base != null && base.status in 200..299

            for (c in rowCells) {
                if (c.identity == baselineName) continue
                if (c.error != null && c.status == 0) continue

                val sim = if (base != null) similarity(base.body, c.body) else 0.0

                if (c.status in 200..299) {
                    if (c.identity.endsWith("@anon")) {
                        out += Finding(
                            "HIGH",
                            "UNAUTHORIZED_ACCESS",
                            tName,
                            value,
                            c.identity,
                            "无凭证访问该接口返回 " + c.status + "（基准身份 " + baselineName +
                                " 返回 " + (base?.status ?: -1) + "）。接口疑似未做鉴权。",
                        )
                    } else if (baseOk && sim >= threshold) {
                        out += Finding(
                            "HIGH",
                            "HORIZONTAL_IDOR",
                            tName,
                            value,
                            c.identity,
                            "身份 " + c.identity + " 访问该资源返回 " + c.status +
                                "，响应体与基准身份 " + baselineName + " 的相似度为 " + round2(sim) +
                                "（>= " + threshold + "）—— 极可能读到了同一份对象数据，构成水平越权。",
                        )
                    } else {
                        out += Finding(
                            "MEDIUM",
                            "CROSS_IDENTITY_DIFFERENT_BODY",
                            tName,
                            value,
                            c.identity,
                            "身份 " + c.identity + " 访问返回 " + c.status +
                                "，响应体与基准不同（相似度 " + round2(sim) + "）。可能各自数据，也可能读到他人数据，建议人工核对。",
                        )
                    }
                } else if (c.status == 401 || c.status == 403) {
                    out += Finding(
                        "INFO",
                        "PROTECTED",
                        tName,
                        value,
                        c.identity,
                        "身份 " + c.identity + " 被拒绝（" + c.status + "），鉴权正常。",
                    )
                }
            }

            // 参数型 IDOR：基准身份用「非原始值」仍拿到 2xx
            if (baseOk && value.isNotBlank() && base != null && !base.originUrl.contains(value)) {
                out += Finding(
                    "HIGH",
                    "PARAM_IDOR",
                    tName,
                    value,
                    baselineName,
                    "把参数改为 " + value + " 后，基准身份仍拿到 " + base.status +
                        "。若该值不属于当前身份，说明服务端未校验对象归属，可直接改 ID 读他人数据。",
                )
            }
        }
        return out
    }

    // ---------------------------------------------------------------- HTTP

    private suspend fun httpCall(
        url: String,
        method: String,
        headers: Map<String, String>,
        body: String?,
        timeoutMs: Int,
    ): HttpResult = withContext(Dispatchers.IO) {
        val started = System.currentTimeMillis()
        var conn: HttpURLConnection? = null
        try {
            val u = URL(url)
            conn = u.openConnection() as HttpURLConnection
            val m = if (method.isBlank()) "GET" else method.uppercase()
            conn.requestMethod = m
            conn.instanceFollowRedirects = true
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            conn.useCaches = false
            headers.forEach { (k, v) ->
                if (k.isNotBlank()) {
                    try {
                        conn.setRequestProperty(k, v)
                    } catch (_: Exception) {
                    }
                }
            }
            val sendBody = body != null && m != "GET" && m != "HEAD"
            if (sendBody) {
                conn.doOutput = true
                val bytes = body!!.toByteArray(StandardCharsets.UTF_8)
                conn.setFixedLengthStreamingMode(bytes.size)
                conn.outputStream.use { it.write(bytes) }
            }
            val code = conn.responseCode
            val text = try {
                val stream: InputStream? = if (code in 200..399) conn.inputStream else conn.errorStream
                if (stream == null) "" else stream.use { readLimited(it, BODY_LIMIT) }
            } catch (_: Exception) {
                ""
            }
            HttpResult(true, code, text, null, System.currentTimeMillis() - started)
        } catch (e: Exception) {
            HttpResult(false, 0, "", e.message ?: e.javaClass.simpleName, System.currentTimeMillis() - started)
        } finally {
            try {
                conn?.disconnect()
            } catch (_: Exception) {
            }
        }
    }

    private fun readLimited(input: InputStream, limit: Int): String {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(8192)
        var total = 0
        while (total < limit) {
            val n = try {
                input.read(buf)
            } catch (_: Exception) {
                -1
            }
            if (n <= 0) break
            val take = if (n > limit - total) limit - total else n
            out.write(buf, 0, take)
            total += take
        }
        return String(out.toByteArray(), StandardCharsets.UTF_8)
    }

    // ---------------------------------------------------------------- 参数替换

    private fun substituteQuery(url: String, param: String, value: String): String {
        val qIdx = url.indexOf('?')
        if (qIdx < 0) return url
        val head = url.substring(0, qIdx)
        val query = url.substring(qIdx + 1)
        val hashIdx = query.indexOf('#')
        val frag = if (hashIdx >= 0) query.substring(hashIdx) else ""
        val pure = if (hashIdx >= 0) query.substring(0, hashIdx) else query

        var hit = false
        val rebuilt = pure.split('&').joinToString("&") { pair ->
            val eq = pair.indexOf('=')
            if (eq > 0 && pair.substring(0, eq) == param) {
                hit = true
                param + "=" + value
            } else {
                pair
            }
        }
        return if (!hit) url else head + "?" + rebuilt + frag
    }

    private fun substituteBody(body: String, param: String, value: String): String {
        val jsonRe = Regex("\"(" + Regex.escape(param) + ")\"\\s*:\\s*(\"[^\"]*\"|[^,}\\s]+)")
        if (jsonRe.containsMatchIn(body)) {
            return jsonRe.replace(body) { m ->
                val key = m.groupValues[1]
                val raw = m.groupValues[2]
                if (raw.startsWith("\"")) "\"" + key + "\":\"" + value + "\"" else "\"" + key + "\":" + value
            }
        }
        val formRe = Regex("(^|[&?])(" + Regex.escape(param) + "=)([^&]*)")
        if (formRe.containsMatchIn(body)) {
            return formRe.replace(body) { m -> m.groupValues[1] + m.groupValues[2] + value }
        }
        return body
    }

    // ---------------------------------------------------------------- 相似度

    private fun compact(s: String): String = s.replace(Regex("\\s+"), " ").trim()

    private fun shingles(s: String, n: Int): Set<String> {
        if (s.isEmpty()) return emptySet()
        if (s.length <= n) return setOf(s)
        val set = HashSet<String>(s.length)
        var i = 0
        while (i + n <= s.length) {
            set.add(s.substring(i, i + n))
            i++
        }
        return set
    }

    /** 4-gram Jaccard 相似度（空白归一化，控制计算量） */
    private fun similarity(a: String, b: String): Double {
        val na = compact(a).take(SIM_MAX_CHARS)
        val nb = compact(b).take(SIM_MAX_CHARS)
        if (na.isEmpty() && nb.isEmpty()) return 1.0
        if (na.isEmpty() || nb.isEmpty()) return 0.0
        if (na == nb) return 1.0
        val sa = shingles(na, 4)
        val sb = shingles(nb, 4)
        if (sa.isEmpty() && sb.isEmpty()) return 1.0
        var inter = 0
        for (x in sa) {
            if (sb.contains(x)) inter++
        }
        val union = sa.size + sb.size - inter
        return if (union <= 0) 0.0 else inter.toDouble() / union.toDouble()
    }

    // ---------------------------------------------------------------- 小工具

    private fun round2(v: Double): Double = Math.round(v * 100.0) / 100.0

    private fun truncate(s: String, n: Int): String = if (s.length <= n) s else s.substring(0, n) + "…(截断)"

    private fun splitCsv(raw: String): List<String> =
        raw.split(',').map { it.trim() }.filter { it.isNotBlank() }

    private fun shortPath(url: String): String {
        val noScheme = url.substringAfter("://", url)
        val slash = noScheme.indexOf('/')
        if (slash < 0) return "/"
        val pathAndQuery = noScheme.substring(slash)
        val q = pathAndQuery.indexOf('?')
        val path = if (q >= 0) pathAndQuery.substring(0, q) else pathAndQuery
        return truncate(path, 40)
    }

    /** 脱敏 URL 中的敏感参数值 */
    private fun redactUrl(url: String): String {
        val q = url.indexOf('?')
        if (q < 0) return url
        val head = url.substring(0, q)
        val query = url.substring(q + 1)
        val masked = query.split('&').joinToString("&") { pair ->
            val eq = pair.indexOf('=')
            if (eq <= 0) {
                pair
            } else {
                val k = pair.substring(0, eq)
                val v = pair.substring(eq + 1)
                if (isSensitiveKey(k) && v.length > 12) k + "=" + v.take(4) + "***" else pair
            }
        }
        return head + "?" + masked
    }

    private fun isSensitiveKey(k: String): Boolean {
        val lk = k.lowercase()
        return lk.contains("token") || lk.contains("sign") || lk.contains("secret") ||
            lk.contains("key") || lk.contains("auth") || lk.contains("session") || lk.contains("password")
    }

    private fun isAuthHeader(k: String): Boolean {
        val lk = k.lowercase()
        return lk == "cookie" || lk == "authorization" || lk.contains("token") ||
            lk.contains("auth") || lk.contains("session") || lk.contains("api-key")
    }

    private fun isForbiddenHeader(k: String): Boolean {
        val lk = k.lowercase()
        return lk == "host" || lk == "content-length" || lk == "connection" ||
            lk == "keep-alive" || lk == "transfer-encoding" || lk == "upgrade" ||
            lk.startsWith("proxy-")
    }
}
