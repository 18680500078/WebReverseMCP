package com.webreverse.mcp.mcp.tools

import com.webreverse.mcp.core.common.permission.PermissionScope
import com.webreverse.mcp.core.common.permission.RiskLevel
import com.webreverse.mcp.core.mcp.McpTool
import com.webreverse.mcp.core.mcp.McpToolResult
import com.webreverse.mcp.core.mcp.ToolCategory
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Fingerprint Tools：反检测与浏览器指纹控制。
 *
 * - fingerprint.status 查看当前 stealth/反检测状态
 * - fingerprint.noise  注入 canvas/webgl 噪声，使指纹每次会话随机化，对抗基于指纹的风控关联
 */
object FingerprintTools {

    fun all(deps: ToolDependencies): List<McpTool> {
        val f = ToolFactory(deps)

        return listOf(
            f.tool(
                "fingerprint.status",
                "查看当前浏览器的反检测(stealth)状态与环境指纹快照（UA/platform/language/canvas/webgl/webdriver 等），用于判断是否需要注入反检测。",
                ToolCategory.PAGE,
                PermissionScope.READ_PAGE,
                RiskLevel.LOW,
            ) { _ ->
                val session = deps.activeSession()
                val env = session.engine.evaluateJavascript(com.webreverse.mcp.browser.engine.util.JsScripts.environmentScript())
                val stealth = session.engine.evaluateJavascript("typeof window.__WRMCP_STEALTH__ !== 'undefined' ? 'true' : 'false'")
                McpToolResult.json(
                    buildJsonObject {
                        put("stealthActive", JsonPrimitive(stealth == "true"))
                        put("environment", JsonPrimitive(env ?: "(无法读取)"))
                        put("hint", JsonPrimitive("stealth 未启用时用 browser.set_stealth 注入；指纹噪声用 fingerprint.noise 随机化 canvas/webgl"))
                    },
                )
            },

            f.tool(
                "fingerprint.noise",
                "注入 canvas/webgl 噪声脚本，使 2D/WebGL 指纹每次会话产生随机差异，破坏跨会话的风控指纹关联。注入后 fingerprint.status 的 canvas/webgl 值会随机变化。",
                ToolCategory.PAGE,
                PermissionScope.MODIFY_PAGE,
                RiskLevel.MEDIUM,
            ) { _ ->
                val session = deps.activeSession()
                val noiseScript = """
                    (function(){
                      if (window.__WRMCP_NOISE__) return 'already';
                      window.__WRMCP_NOISE__ = true;
                      // 2D canvas 噪声：改写 toDataURL/toBlob，叠加随机像素
                      try {
                        var _toDataURL = HTMLCanvasElement.prototype.toDataURL;
                        HTMLCanvasElement.prototype.toDataURL = function() {
                          var ctx = this.getContext('2d');
                          if (ctx) {
                            var d = ctx.getImageData(0, 0, this.width, this.height);
                            var r = Math.floor(Math.random() * 1e9);
                            for (var i = 0; i < d.data.length; i += 4) {
                              d.data[i] = (d.data[i] + (r >> (i % 24)) & 0xFF);
                            }
                            ctx.putImageData(d, 0, 0);
                          }
                          return _toDataURL.apply(this, arguments);
                        };
                      } catch(e){}
                      // WebGL 噪声：改写 getParameter 对部分项返回噪声
                      try {
                        var glProto = WebGLRenderingContext.prototype;
                        var _getParam = glProto.getParameter;
                        glProto.getParameter = function(p) {
                          var v = _getParam.apply(this, arguments);
                          if (p === 37445 || p === 37446) { return v + '_' + Math.random().toString(36).slice(2,6); }
                          return v;
                        };
                      } catch(e){}
                      return 'injected';
                    })();
                """.trimIndent()
                val result = session.engine.evaluateJavascript(noiseScript)
                McpToolResult.json(
                    buildJsonObject {
                        put("injected", JsonPrimitive(result != null))
                        put("result", JsonPrimitive(result ?: "(null)"))
                        put("hint", JsonPrimitive("噪声已注入当前页。重新调用 fingerprint.status 或重新加载可观察 canvas/webgl 指纹随机化"))
                    },
                )
            },
        )
    }
}
