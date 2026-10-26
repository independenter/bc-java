package org.bouncycastle.learning.trace;

import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * HTML 生成器 —— 把追踪事件渲染为可交互的 HTML 页面。
 *
 * <p>流程图设计（面向学习）：
 * <ul>
 *   <li>主流程图垂直布局：开始 → 密钥生成 → ZA → e → 签名 → 验签 → 结束</li>
 *   <li>菱形用 clip-path 绘制（外框色 + 内填色两层），文字直接放中心不用旋转</li>
 *   <li>循环节点内嵌<b>子流程图</b>：取 bit → ◇bit=1?◇ → double+add / double only → 合并 → j++，
 *       每次迭代根据 bitVal 高亮对应分支</li>
 *   <li>循环内的 doublePoint/add 通过 "loopName:ecOp" 复合分组归属到循环节点，避免主流程图闪烁</li>
 * </ul>
 */
public class HtmlGenerator
{
    public static String generate(Tracer.TraceContext ctx)
    {
        List<TraceEvent> events = ctx.getEvents();
        String algorithm = ctx.getAlgorithm();
        FlowDefinition flow = resolveFlow(algorithm, ctx.getFlowKey());
        String flowName = flow.getName();
        // 标题优先用测试方法的用途（@TraceExecution.value()），流程图名只作副标题
        String title = ctx.getTitle().isEmpty() ? flowName : ctx.getTitle();
        reportMappingProblems(flow, events);
        StringBuilder html = new StringBuilder();

        html.append("<!DOCTYPE html>\n");
        html.append("<!-- flow: ").append(escapeHtml(flowName)).append(" | title: ")
            .append(escapeHtml(title)).append(" -->\n");
        html.append("<html lang='zh-CN'>\n");
        html.append("<head>\n");
        html.append("  <meta charset='UTF-8'>\n");
        html.append("  <title>").append(escapeHtml(title)).append(" · 流程追踪</title>\n");
        html.append("  <style>\n");
        html.append(getCss());
        html.append("  </style>\n");
        html.append("</head>\n");
        html.append("<body>\n");

        html.append("  <div class='header'>\n");
        html.append("    <h1>").append(escapeHtml(title));
        if (!flowName.equals(title))
        {
            html.append(" <span class='flow-sub'>流程图：").append(escapeHtml(flowName)).append("</span>");
        }
        html.append("</h1>\n");
        html.append("    <div class='stats'>\n");
        html.append("      <span>Steps: ").append(events.size()).append("</span>\n");
        double totalMs = events.stream().mapToDouble(TraceEvent::getDurationMillis).sum();
        html.append("      <span>Total: ").append(String.format("%.2f", totalMs)).append(" ms</span>\n");
        html.append("    </div>\n");
        html.append("  </div>\n");

        html.append("  <div class='controls'>\n");
        html.append("    <button onclick='firstStep()'>⏮</button>\n");
        html.append("    <button onclick='prevStep()'>◀</button>\n");
        html.append("    <button onclick='togglePlay()' id='playBtn'>▶</button>\n");
        html.append("    <button onclick='nextStep()'>▶</button>\n");
        html.append("    <button onclick='lastStep()'>⏭</button>\n");
        html.append("    <span class='step-info' id='stepInfo'>Step 0 / ").append(events.size()).append("</span>\n");
        html.append("    <label>Speed: <input type='range' id='speed' min='50' max='2000' value='300' step='50'> <span id='speedVal'>300ms</span></label>\n");
        html.append("  </div>\n");

        html.append("  <div class='main'>\n");
        html.append("    <div class='flowchart-panel'>\n");
        html.append("      <h2>流程图谱</h2>\n");
        html.append("      <div class='flowchart' id='flowchart'>\n");
        html.append(renderFlowchart(flow));
        html.append("      </div>\n");
        html.append("    </div>\n");

        html.append("    <div class='right-side'>\n");
        html.append("      <div class='steps-panel'>\n");
        html.append("        <h2>执行步骤</h2>\n");
        html.append("        <div class='step-list' id='stepList'>\n");
        for (TraceEvent event : events)
        {
            String groupClass = "group-" + event.getGroup().replaceAll("[^a-zA-Z0-9]", "");
            html.append("          <div class='step-item ").append(groupClass).append("' data-step='")
                .append(event.getStepNumber()).append("' onclick='goToStep(")
                .append(event.getStepNumber()).append(")'>\n");
            html.append("            <span class='step-num'>#").append(event.getStepNumber()).append("</span>\n");
            html.append("            <span class='op-name'>").append(escapeHtml(event.getOperation())).append("</span>\n");
            html.append("            <span class='group-badge'>").append(event.getGroup()).append("</span>\n");
            html.append("            <span class='duration'>").append(String.format("%.3f", event.getDurationMillis())).append("ms</span>\n");
            html.append("          </div>\n");
        }
        html.append("        </div>\n");
        html.append("      </div>\n");

        html.append("      <div class='detail-panel'>\n");
        html.append("        <h2>详细信息</h2>\n");
        html.append("        <div class='detail-view' id='detailView'>\n");
        html.append("          <p class='placeholder'>点击步骤查看详情</p>\n");
        html.append("        </div>\n");
        html.append("      </div>\n");
        html.append("    </div>\n");
        html.append("  </div>\n");

        html.append("  <script>\n");
        html.append(getJavaScript(events, flow));
        html.append("  </script>\n");

        html.append("</body>\n");
        html.append("</html>\n");

        return html.toString();
    }

    private static FlowDefinition buildSm2Flow()
    {
        FlowDefinition flow = new FlowDefinition("SM2 签名验签");

        flow.addNode("start", "开始", FlowNodeType.TERMINAL, "start");
        flow.addNode("keygen", "生成密钥对 (d, P=dG)", FlowNodeType.OPERATION, "keygen", "私钥 d，公钥 P");
        flow.addNode("computeZA", "计算 ZA = SM3(ENTL||ID||a||b||Gx||Gy||Px||Py)", FlowNodeType.OPERATION, "computeZA", "身份哈希");
        flow.addNode("computeE", "计算 e = SM3(ZA||M)", FlowNodeType.OPERATION, "computeE", "消息哈希");

        flow.addNode("sm2SignGroup", "SM2 签名", FlowNodeType.GROUP, "sm2Sign", "签名整体流程");
        flow.addNode("mul_kG", "k·G 标量乘", FlowNodeType.LOOP, "mul_kG", "double-and-add：逐位扫描 k");
        flow.addNode("computeR", "r = (e + x₁) mod n", FlowNodeType.OPERATION, "computeR", "计算 r");
        flow.addNode("checkR", "r == 0 ?", FlowNodeType.DECISION, "checkR", "判断 r");
        flow.addNode("computeS", "s = (k - rd)(1+d)⁻¹ mod n", FlowNodeType.OPERATION, "computeS", "计算 s");
        flow.addNode("checkRK", "r + k ≡ 0 (mod n) ?", FlowNodeType.DECISION, "checkRK", "判断 r+k");
        flow.addNode("returnRS", "返回 (r, s)", FlowNodeType.OPERATION, "returnRS", "签名结果");

        flow.addNode("sm2VerifyGroup", "SM2 验签", FlowNodeType.GROUP, "sm2Verify", "验签整体流程");
        flow.addNode("checkFormat", "r,s ∈ [1,n-1] ?", FlowNodeType.DECISION, "checkFormat", "格式检查");
        flow.addNode("computeT", "t = (r + s) mod n", FlowNodeType.OPERATION, "computeT", "计算 t");
        flow.addNode("checkT", "t == 0 ?", FlowNodeType.DECISION, "checkT", "判断 t");
        flow.addNode("mul_sG", "s·G 标量乘", FlowNodeType.LOOP, "mul_sG", "double-and-add：逐位扫描 s");
        flow.addNode("mul_tP", "t·P 标量乘", FlowNodeType.LOOP, "mul_tP", "double-and-add：逐位扫描 t");
        flow.addNode("addPoints", "(x₁,y₁) = sG + tP", FlowNodeType.OPERATION, "ecOp", "点加");
        flow.addNode("checkPoint", "point == O ?", FlowNodeType.DECISION, "checkPoint", "判断点");
        flow.addNode("finalCheck", "(e + x₁) mod n == r ?", FlowNodeType.DECISION, "finalCheck", "最终核对");
        flow.addNode("end", "结束", FlowNodeType.TERMINAL, "end");

        flow.addEdge("start", "keygen");
        flow.addEdge("keygen", "computeZA");
        flow.addEdge("computeZA", "computeE");
        flow.addEdge("computeE", "sm2SignGroup");
        flow.addEdge("sm2SignGroup", "mul_kG");
        flow.addEdge("mul_kG", "computeR");
        flow.addEdge("computeR", "checkR");
        flow.addEdge("checkR", "computeS", "no");
        flow.addEdge("computeS", "checkRK");
        flow.addEdge("checkRK", "returnRS", "no");
        flow.addEdge("returnRS", "sm2VerifyGroup");
        flow.addEdge("sm2VerifyGroup", "checkFormat");
        flow.addEdge("checkFormat", "computeT", "yes");
        flow.addEdge("computeT", "checkT");
        flow.addEdge("checkT", "mul_sG", "no");
        flow.addEdge("mul_sG", "mul_tP");
        flow.addEdge("mul_tP", "addPoints");
        flow.addEdge("addPoints", "checkPoint");
        flow.addEdge("checkPoint", "finalCheck", "no");
        flow.addEdge("finalCheck", "end", "yes");

        flow.setStartNodeId("start");
        return flow;
    }

    private static FlowDefinition resolveFlow(String algorithm, String flowKey)
    {
        FlowDefinition flow = Flows.resolve(flowKey);
        if (flow != null)
        {
            return flow;
        }
        if (flowKey != null && !flowKey.isEmpty())
        {
            System.err.println("[Tracer] 未知流程图 key: " + flowKey + "，回退到 " + algorithm + " 默认流程图");
        }
        return buildFlowForAlgorithm(algorithm);
    }

    /**
     * 校验事件分组能否落到流程节点上：
     * 未映射的 group 会让光标无处可跳，重复 group 会让多个节点同时高亮 —— 两种都打印警告。
     */
    private static void reportMappingProblems(FlowDefinition flow, List<TraceEvent> events)
    {
        java.util.Set<String> nodeGroups = new java.util.LinkedHashSet<>();
        java.util.Set<String> duplicateGroups = new java.util.LinkedHashSet<>();
        for (FlowNode node : flow.getNodes().values())
        {
            if (!nodeGroups.add(node.getGroup()))
            {
                duplicateGroups.add(node.getGroup());
            }
        }

        java.util.Set<String> unmapped = new java.util.LinkedHashSet<>();
        java.util.Set<String> missingSubSteps = new java.util.LinkedHashSet<>();
        for (TraceEvent event : events)
        {
            String group = event.getGroup();
            String base = baseGroup(group);
            if (!nodeGroups.contains(base))
            {
                unmapped.add(base);
                continue;
            }
            // 复合 group 只落到组标题、没有自己的子步骤节点：光标跳不到具体一步
            if (group.indexOf(':') >= 0 && !nodeGroups.contains(group))
            {
                FlowNode baseNode = flow.findNodeByGroup(base);
                if (baseNode != null && baseNode.getType() == FlowNodeType.GROUP)
                {
                    missingSubSteps.add(group);
                }
            }
        }

        // 顺序校验：各节点“首次出现”的步骤号必须与流程图中节点顺序一致。
        // GROUP 是区块标题、LOOP 内部事件会重复，二者不参与顺序判定。
        Map<String, Integer> firstStep = new LinkedHashMap<>();
        for (TraceEvent event : events)
        {
            String group = nodeGroups.contains(event.getGroup()) ? event.getGroup() : baseGroup(event.getGroup());
            if (nodeGroups.contains(group))
            {
                firstStep.putIfAbsent(group, event.getStepNumber());
            }
        }
        int lastStep = -1;
        String lastGroup = null;
        java.util.List<String> outOfOrder = new java.util.ArrayList<>();
        for (FlowNode node : flow.getNodes().values())
        {
            Integer step = firstStep.get(node.getGroup());
            if (step == null || node.getType() == FlowNodeType.GROUP)
            {
                continue;
            }
            if (step < lastStep)
            {
                outOfOrder.add(node.getGroup() + "(#" + step + " < " + lastGroup + " #" + lastStep + ")");
            }
            else
            {
                lastStep = step;
                lastGroup = node.getGroup();
            }
        }

        if (!duplicateGroups.isEmpty())
        {
            System.err.println("[Tracer] 流程图 " + flow.getName() + " 存在重复 group 节点: " + duplicateGroups);
        }
        if (!unmapped.isEmpty())
        {
            System.err.println("[Tracer] 流程图 " + flow.getName() + " 缺少这些 group 的节点: " + unmapped);
        }
        if (!missingSubSteps.isEmpty())
        {
            System.err.println("[Tracer] 流程图 " + flow.getName() + " 缺少这些子步骤节点: " + missingSubSteps);
        }
        if (!outOfOrder.isEmpty())
        {
            System.err.println("[Tracer] 流程图 " + flow.getName() + " 事件顺序与流程节点顺序不一致: " + outOfOrder);
        }
    }

    private static String baseGroup(String group)
    {
        int idx = group.indexOf(':');
        return idx < 0 ? group : group.substring(0, idx);
    }

    private static FlowDefinition buildFlowForAlgorithm(String algorithm)
    {
        switch (algorithm.toUpperCase())
        {
            case "SM2":
                return buildSm2Flow();
            case "SM3":
                return buildSm3Flow();
            case "SM4":
                return buildSm4Flow();
            case "RSA":
                return buildRsaFlow();
            case "SM9":
                return buildSm9Flow();
            case "PQC":
            case "MLKEM":
            case "MLDSA":
            case "SLHDSA":
                return buildPqcFlow();
            case "THRESHOLD":
                return buildThresholdFlow();
            case "MULTISIG":
                return buildMultisigFlow();
            case "INTERACTIVE":
                return buildInteractiveFlow();
            default:
                return buildGenericFlow(algorithm);
        }
    }

    private static FlowDefinition buildSm3Flow()
    {
        FlowDefinition flow = new FlowDefinition("SM3 哈希");

        flow.addNode("start", "开始", FlowNodeType.TERMINAL, "start");
        flow.addNode("pad", "MD 填充: m‖0x80‖0^k‖len₆₄", FlowNodeType.OPERATION, "pad", "补到 64 字节倍数");
        flow.addNode("split", "切分为 64 字节块", FlowNodeType.OPERATION, "split", "B₀..Bₙ₋₁");
        flow.addNode("initV", "V₀ = IV (8 个初始链接字)", FlowNodeType.OPERATION, "initV", "A..H 初值");
        flow.addNode("cfLoop", "压缩函数循环", FlowNodeType.LOOP, "cfLoop", "Vᵢ = CF(Vᵢ₋₁, Bᵢ)");
        flow.addNode("expand", "W 扩展: W₀..W₆₇", FlowNodeType.OPERATION, "expand", "消息扩展");
        flow.addNode("compress", "64 轮压缩", FlowNodeType.LOOP, "compress", "FF/GG/P0/P1");
        flow.addNode("finalize", "输出 Vₙ = A..H → 32 字节", FlowNodeType.OPERATION, "finalize", "大端序列化");
        flow.addNode("end", "结束", FlowNodeType.TERMINAL, "end");

        flow.addEdge("start", "pad");
        flow.addEdge("pad", "split");
        flow.addEdge("split", "initV");
        flow.addEdge("initV", "cfLoop");
        flow.addEdge("cfLoop", "expand");
        flow.addEdge("expand", "compress");
        flow.addEdge("compress", "finalize", "done");
        flow.addEdge("finalize", "end");

        flow.setStartNodeId("start");
        return flow;
    }

    private static FlowDefinition buildSm4Flow()
    {
        FlowDefinition flow = new FlowDefinition("SM4 分组密码");

        flow.addNode("start", "开始", FlowNodeType.TERMINAL, "start");
        flow.addNode("keyExpand", "密钥扩展: MK → rk₀..rk₃₁", FlowNodeType.OPERATION, "keyExpand", "T 变换 + CK");
        flow.addNode("initReg", "初始化 (X₀,X₁,X₂,X₃)", FlowNodeType.OPERATION, "initReg", "128-bit 分块");
        flow.addNode("roundLoop", "32 轮迭代", FlowNodeType.LOOP, "roundLoop", "Xᵢ₊₄ = Xᵢ ⊕ T(Xᵢ₊₁⊕Xᵢ₊₂⊕Xᵢ₊₃⊕rkᵢ)");
        flow.addNode("sBox", "S 盒替换 (τ)", FlowNodeType.OPERATION, "sBox", "非线性层");
        flow.addNode("linear", "线性变换 L", FlowNodeType.OPERATION, "linear", "⊕ rotl(·,2) ⊕ rotl(·,10) ⊕ rotl(·,18) ⊕ rotl(·,24)");
        flow.addNode("reverse", "反序变换 (X₃₅,X₃₄,X₃₃,X₃₂)", FlowNodeType.OPERATION, "reverse", "Y = (Y₀,Y₁,Y₂,Y₃)");
        flow.addNode("end", "结束", FlowNodeType.TERMINAL, "end");

        flow.addEdge("start", "keyExpand");
        flow.addEdge("keyExpand", "initReg");
        flow.addEdge("initReg", "roundLoop");
        flow.addEdge("roundLoop", "sBox");
        flow.addEdge("sBox", "linear");
        flow.addEdge("linear", "reverse", "32 轮完成");
        flow.addEdge("reverse", "end");

        flow.setStartNodeId("start");
        return flow;
    }

    private static FlowDefinition buildRsaFlow()
    {
        FlowDefinition flow = new FlowDefinition("RSA 公钥密码");

        flow.addNode("start", "开始", FlowNodeType.TERMINAL, "start");
        flow.addNode("keygen", "生成密钥对", FlowNodeType.OPERATION, "keygen", "p,q → n,φ(n),e,d");
        flow.addNode("selectP", "选取大素数 p", FlowNodeType.OPERATION, "selectP", "随机 + 素性检测");
        flow.addNode("selectQ", "选取大素数 q", FlowNodeType.OPERATION, "selectQ", "随机 + 素性检测");
        flow.addNode("computeN", "n = p·q", FlowNodeType.OPERATION, "computeN", "模数");
        flow.addNode("computePhi", "φ(n) = (p−1)(q−1)", FlowNodeType.OPERATION, "computePhi", "欧拉函数");
        flow.addNode("selectE", "选取 e: gcd(e,φ)=1", FlowNodeType.OPERATION, "selectE", "通常 65537");
        flow.addNode("computeD", "d = e⁻¹ mod φ(n)", FlowNodeType.OPERATION, "computeD", "扩展欧几里得");
        flow.addNode("encrypt", "加密: c = mᵉ mod n", FlowNodeType.LOOP, "encrypt", "快速幂");
        flow.addNode("decrypt", "解密: m = cᵈ mod n", FlowNodeType.LOOP, "decrypt", "快速幂");
        flow.addNode("end", "结束", FlowNodeType.TERMINAL, "end");

        flow.addEdge("start", "keygen");
        flow.addEdge("keygen", "selectP");
        flow.addEdge("selectP", "selectQ");
        flow.addEdge("selectQ", "computeN");
        flow.addEdge("computeN", "computePhi");
        flow.addEdge("computePhi", "selectE");
        flow.addEdge("selectE", "computeD");
        flow.addEdge("computeD", "encrypt");
        flow.addEdge("encrypt", "decrypt");
        flow.addEdge("decrypt", "end");

        flow.setStartNodeId("start");
        return flow;
    }

    private static FlowDefinition buildSm9Flow()
    {
        FlowDefinition flow = new FlowDefinition("SM9 标识密码");

        flow.addNode("start", "开始", FlowNodeType.TERMINAL, "start");
        flow.addNode("setup", "系统设置: 生成主密钥与公共参数", FlowNodeType.OPERATION, "setup", "KGS 执行");
        flow.addNode("keygen", "用户私钥生成: dA = H₁(IDA)·ks", FlowNodeType.OPERATION, "keygen", "基于身份");
        flow.addNode("pairing", "双线性对: e(P,Q)", FlowNodeType.LOOP, "pairing", "R-ate 对");
        flow.addNode("sign", "签名: (h,s) = Sign(dA, M)", FlowNodeType.OPERATION, "sign", "用户执行");
        flow.addNode("verify", "验签: 核对等式", FlowNodeType.OPERATION, "verify", "验证者执行");
        flow.addNode("encrypt", "加密: CB = Enc(KB, M)", FlowNodeType.OPERATION, "encrypt", "发送方执行");
        flow.addNode("decrypt", "解密: M = Dec(dB, CB)", FlowNodeType.OPERATION, "decrypt", "接收方执行");
        flow.addNode("end", "结束", FlowNodeType.TERMINAL, "end");

        flow.addEdge("start", "setup");
        flow.addEdge("setup", "keygen");
        flow.addEdge("keygen", "pairing");
        flow.addEdge("pairing", "sign");
        flow.addEdge("sign", "verify");
        flow.addEdge("verify", "encrypt");
        flow.addEdge("encrypt", "decrypt");
        flow.addEdge("decrypt", "end");

        flow.setStartNodeId("start");
        return flow;
    }

    private static FlowDefinition buildPqcFlow()
    {
        FlowDefinition flow = new FlowDefinition("后量子密码 (PQC)");

        flow.addNode("start", "开始", FlowNodeType.TERMINAL, "start");
        flow.addNode("mlkem", "ML-KEM (晶格密钥封装)", FlowNodeType.OPERATION, "mlkem", "基于 LWE");
        flow.addNode("mldsa", "ML-DSA (晶格签名)", FlowNodeType.OPERATION, "mldsa", "基于 Module-LWE");
        flow.addNode("slhdsa", "SLH-DSA (哈希签名)", FlowNodeType.OPERATION, "slhdsa", "基于哈希");
        flow.addNode("keygen", "密钥生成", FlowNodeType.LOOP, "keygen", "采样 +  NTT");
        flow.addNode("encap", "封装/签名", FlowNodeType.OPERATION, "encap", "多项式运算");
        flow.addNode("decap", "解封装/验签", FlowNodeType.OPERATION, "decap", "纠错解码");
        flow.addNode("end", "结束", FlowNodeType.TERMINAL, "end");

        flow.addEdge("start", "mlkem");
        flow.addEdge("mlkem", "mldsa");
        flow.addEdge("mldsa", "slhdsa");
        flow.addEdge("slhdsa", "keygen");
        flow.addEdge("keygen", "encap");
        flow.addEdge("encap", "decap");
        flow.addEdge("decap", "end");

        flow.setStartNodeId("start");
        return flow;
    }

    private static FlowDefinition buildThresholdFlow()
    {
        FlowDefinition flow = new FlowDefinition("门限签名 (t,n)");

        flow.addNode("start", "开始", FlowNodeType.TERMINAL, "start");
        flow.addNode("setup", "系统初始化: 生成 (t,n) 门限参数", FlowNodeType.OPERATION, "setup", "Shamir 秘密共享");
        flow.addNode("keyDist", "密钥分发: 每个参与者获得份额", FlowNodeType.OPERATION, "keyDist", "si = f(i)");
        flow.addNode("partialSign", "部分签名: 每个参与者生成 σᵢ", FlowNodeType.LOOP, "partialSign", "t 个参与者");
        flow.addNode("combine", "签名合成: Lagrange 插值", FlowNodeType.OPERATION, "combine", "σ = Σ λᵢ·σᵢ");
        flow.addNode("verify", "验签: 验证合成签名", FlowNodeType.OPERATION, "verify", "标准验签算法");
        flow.addNode("end", "结束", FlowNodeType.TERMINAL, "end");

        flow.addEdge("start", "setup");
        flow.addEdge("setup", "keyDist");
        flow.addEdge("keyDist", "partialSign");
        flow.addEdge("partialSign", "combine");
        flow.addEdge("combine", "verify");
        flow.addEdge("verify", "end");

        flow.setStartNodeId("start");
        return flow;
    }

    private static FlowDefinition buildMultisigFlow()
    {
        FlowDefinition flow = new FlowDefinition("多重签名");

        flow.addNode("start", "开始", FlowNodeType.TERMINAL, "start");
        flow.addNode("keyAgg", "密钥聚合: P = Σ Pᵢ", FlowNodeType.OPERATION, "keyAgg", "公钥聚合");
        flow.addNode("nonceGen", "nonce 生成: 每个参与者生成 Rᵢ", FlowNodeType.LOOP, "nonceGen", "随机数");
        flow.addNode("nonceAgg", "nonce 聚合: R = Σ Rᵢ", FlowNodeType.OPERATION, "nonceAgg", "聚合 nonce");
        flow.addNode("partialSig", "部分签名: 每个参与者生成 sᵢ", FlowNodeType.LOOP, "partialSig", "本地计算");
        flow.addNode("sigAgg", "签名聚合: s = Σ sᵢ", FlowNodeType.OPERATION, "sigAgg", "聚合签名");
        flow.addNode("verify", "验签: (R,s) 对聚合公钥 P", FlowNodeType.OPERATION, "verify", "标准验签");
        flow.addNode("end", "结束", FlowNodeType.TERMINAL, "end");

        flow.addEdge("start", "keyAgg");
        flow.addEdge("keyAgg", "nonceGen");
        flow.addEdge("nonceGen", "nonceAgg");
        flow.addEdge("nonceAgg", "partialSig");
        flow.addEdge("partialSig", "sigAgg");
        flow.addEdge("sigAgg", "verify");
        flow.addEdge("verify", "end");

        flow.setStartNodeId("start");
        return flow;
    }

    private static FlowDefinition buildInteractiveFlow()
    {
        FlowDefinition flow = new FlowDefinition("交互式协同签名");

        flow.addNode("start", "开始", FlowNodeType.TERMINAL, "start");
        flow.addNode("setup", "系统初始化", FlowNodeType.OPERATION, "setup", "参数生成");
        flow.addNode("round1", "轮次 1: 承诺交换", FlowNodeType.OPERATION, "round1", "commitment");
        flow.addNode("round2", "轮次 2: 挑战生成", FlowNodeType.OPERATION, "round2", "challenge");
        flow.addNode("round3", "轮次 3: 响应交换", FlowNodeType.OPERATION, "round3", "response");
        flow.addNode("combine", "签名合成", FlowNodeType.OPERATION, "combine", "最终签名");
        flow.addNode("verify", "验签", FlowNodeType.OPERATION, "verify", "验证签名");
        flow.addNode("end", "结束", FlowNodeType.TERMINAL, "end");

        flow.addEdge("start", "setup");
        flow.addEdge("setup", "round1");
        flow.addEdge("round1", "round2");
        flow.addEdge("round2", "round3");
        flow.addEdge("round3", "combine");
        flow.addEdge("combine", "verify");
        flow.addEdge("verify", "end");

        flow.setStartNodeId("start");
        return flow;
    }

    private static FlowDefinition buildGenericFlow(String algorithm)
    {
        FlowDefinition flow = new FlowDefinition(algorithm + " 算法");

        flow.addNode("start", "开始", FlowNodeType.TERMINAL, "start");
        flow.addNode("step1", "步骤 1", FlowNodeType.OPERATION, "step1", "");
        flow.addNode("step2", "步骤 2", FlowNodeType.OPERATION, "step2", "");
        flow.addNode("end", "结束", FlowNodeType.TERMINAL, "end");

        flow.addEdge("start", "step1");
        flow.addEdge("step1", "step2");
        flow.addEdge("step2", "end");

        flow.setStartNodeId("start");
        return flow;
    }

    private static String renderFlowchart(FlowDefinition flow)
    {
        StringBuilder sb = new StringBuilder();

        sb.append("<svg class='flow-arrows' id='flowArrows' width='100%' height='100%'>\n");
        sb.append("  <defs>\n");
        sb.append("    <marker id='arrowhead' markerWidth='10' markerHeight='10' refX='9' refY='3' orient='auto'>\n");
        sb.append("      <polygon points='0 0, 10 3, 0 6' fill='#3498db' />\n");
        sb.append("    </marker>\n");
        sb.append("    <marker id='arrowhead-active' markerWidth='10' markerHeight='10' refX='9' refY='3' orient='auto'>\n");
        sb.append("      <polygon points='0 0, 10 3, 0 6' fill='#e74c3c' />\n");
        sb.append("    </marker>\n");
        sb.append("    <marker id='arrowhead-visited' markerWidth='10' markerHeight='10' refX='9' refY='3' orient='auto'>\n");
        sb.append("      <polygon points='0 0, 10 3, 0 6' fill='#27ae60' />\n");
        sb.append("    </marker>\n");
        sb.append("  </defs>\n");
        sb.append("</svg>\n");

        sb.append("<div class='flow-nodes'>\n");

        for (String nodeId : flow.getNodes().keySet())
        {
            sb.append("  <div class='flow-layer'>\n");
            FlowNode node = flow.getNodes().get(nodeId);
            if (node != null)
            {
                sb.append(renderFlowNode(node));
            }
            sb.append("  </div>\n");
        }

        sb.append("</div>\n");
        return sb.toString();
    }

    private static String renderFlowNode(FlowNode node)
    {
        StringBuilder sb = new StringBuilder();
        String typeClass = "flow-node-" + node.getType().name().toLowerCase();
        String groupClass = "flow-group-" + node.getGroup().replaceAll("[^a-zA-Z0-9]", "");
        String id = node.getId();

        if (node.getType() == FlowNodeType.LOOP)
        {
            return renderLoopNode(node);
        }

        sb.append("    <div class='flow-node ").append(typeClass).append(" ").append(groupClass)
            .append("' data-group='").append(node.getGroup()).append("' id='flow-")
            .append(id).append("'>\n");

        if (node.getType() == FlowNodeType.DECISION)
        {
            sb.append("      <div class='dim-outer' id='dim-outer-").append(id).append("'>\n");
            sb.append("        <div class='dim-inner' id='dim-inner-").append(id).append("'>\n");
            sb.append("          <span class='dim-text'>").append(escapeHtml(node.getLabel())).append("</span>\n");
            sb.append("        </div>\n");
            sb.append("      </div>\n");
        }
        else
        {
            sb.append("      <div class='node-label'>").append(escapeHtml(node.getLabel())).append("</div>\n");
        }

        if (node.getDescription() != null && !node.getDescription().isEmpty())
        {
            sb.append("      <div class='node-desc'>").append(escapeHtml(node.getDescription())).append("</div>\n");
        }

        sb.append("    </div>\n");
        return sb.toString();
    }

    /**
     * 循环节点：虚线框包裹的子流程图，形态由 {@link FlowLoopKind} 决定。
     * 逐位循环画 取位 → 判断 → 双分支；轮数/分块循环画 第 j 轮/块 → 循环体。
     */
    private static String renderLoopNode(FlowNode node)
    {
        StringBuilder sb = new StringBuilder();
        String id = node.getId();
        FlowLoopKind kind = node.getLoopKind();
        String symbol = node.getLoopSymbol().isEmpty() ? loopSymbol(id) : node.getLoopSymbol();

        sb.append("    <div class='loop-wrapper' data-group='").append(node.getGroup())
            .append("' data-loop-id='").append(id)
            .append("' data-loop-kind='").append(kind.name().toLowerCase())
            .append("' data-loop-symbol='").append(escapeHtml(symbol))
            .append("' id='flow-").append(id).append("'>\n");

        // 头部：循环标识 + 迭代计数 + 目的
        sb.append("      <div class='loop-header'>\n");
        sb.append("        <span class='loop-badge'>").append(escapeHtml(id)).append("</span>\n");
        sb.append("        <span class='loop-count' id='loop-count-").append(id).append("'>0 / -</span>\n");
        sb.append("        <span class='loop-goal'>").append(escapeHtml(node.getDescription())).append("</span>\n");
        sb.append("      </div>\n");

        sb.append("      <div class='loop-flow'>\n");

        // 第一步：取位 / 第 j 轮 / 第 j 块
        String title;
        String val;
        if (kind == FlowLoopKind.BIT)
        {
            title = "取 " + symbol + " 的第 j 位";
            val = symbol + "[j] = -";
        }
        else if (kind == FlowLoopKind.ROUND)
        {
            title = "第 j 轮";
            val = "round = -";
        }
        else if (kind == FlowLoopKind.BLOCK)
        {
            title = "第 j 块 / 项";
            val = "item = -";
        }
        else
        {
            title = "第 j 步";
            val = "step = -";
        }
        sb.append("        <div class='lf-step' id='lf-extract-").append(id).append("'>\n");
        sb.append("          <div class='lf-step-title'>").append(escapeHtml(title)).append("</div>\n");
        sb.append("          <div class='lf-step-val' id='lf-bit-").append(id).append("'>")
            .append(escapeHtml(val)).append("</div>\n");
        sb.append("        </div>\n");

        sb.append("        <div class='lf-arrow'>&#8595;</div>\n");

        if (kind == FlowLoopKind.BIT)
        {
            sb.append("        <div class='lf-dim-outer' id='lf-dec-").append(id).append("'>\n");
            sb.append("          <div class='lf-dim-inner'><span>bit = 1 ?</span></div>\n");
            sb.append("        </div>\n");

            sb.append("        <div class='lf-branches'>\n");
            sb.append("          <div class='lf-branch'>\n");
            sb.append("            <span class='lf-tag lf-tag-yes'>yes</span>\n");
            sb.append("            <div class='lf-step lf-branch-step' id='lf-da-").append(id).append("'>double + add</div>\n");
            sb.append("          </div>\n");
            sb.append("          <div class='lf-branch'>\n");
            sb.append("            <span class='lf-tag lf-tag-no'>no</span>\n");
            sb.append("            <div class='lf-step lf-branch-step' id='lf-do-").append(id).append("'>double only</div>\n");
            sb.append("          </div>\n");
            sb.append("        </div>\n");

            sb.append("        <div class='lf-arrow'>&#8595;</div>\n");
        }
        else
        {
            String body = node.getLoopStepLabel().isEmpty() ?
                (kind == FlowLoopKind.ROUND ? "执行轮函数" : "执行循环体") : node.getLoopStepLabel();
            sb.append("        <div class='lf-step' id='lf-body-").append(id).append("'>")
                .append(escapeHtml(body)).append("</div>\n");
            sb.append("        <div class='lf-arrow'>&#8595;</div>\n");
        }

        sb.append("        <div class='lf-step lf-step-inc' id='lf-inc-").append(id).append("'>j++ &#8635;</div>\n");

        sb.append("      </div>\n");

        // 进度条
        sb.append("      <div class='loop-progress-track'>\n");
        sb.append("        <div class='loop-progress-fill' id='progress-").append(id).append("'></div>\n");
        sb.append("      </div>\n");

        sb.append("    </div>\n");
        return sb.toString();
    }

    /** 每个标量乘循环扫的是哪个标量：kG 扫 k，sG 扫 s，tP 扫 t。 */
    private static String loopSymbol(String loopId)
    {
        if ("mul_sG".equals(loopId))
        {
            return "s";
        }
        if ("mul_tP".equals(loopId))
        {
            return "t";
        }
        return "k";
    }

    private static String getCss()
    {
        return "    * { margin: 0; padding: 0; box-sizing: border-box; }\n" +
            "    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; }\n" +
            "    .header { background: #2c3e50; color: white; padding: 15px 20px; display: flex; justify-content: space-between; align-items: center; }\n" +
            "    .header h1 { font-size: 22px; }\n" +
            "    .flow-sub { font-size: 12px; font-weight: normal; color: #bdc3c7; margin-left: 10px; }\n" +
            "    .stats span { margin-left: 20px; font-size: 13px; }\n" +
            "    .controls { background: white; padding: 10px 15px; border-bottom: 1px solid #ddd; display: flex; align-items: center; gap: 8px; }\n" +
            "    .controls button { padding: 6px 14px; font-size: 15px; cursor: pointer; border: 1px solid #ccc; background: white; border-radius: 4px; }\n" +
            "    .controls button:hover { background: #f0f0f0; }\n" +
            "    .step-info { margin-left: 15px; font-weight: bold; font-size: 14px; }\n" +
            "    .controls label { margin-left: auto; display: flex; align-items: center; gap: 8px; font-size: 13px; }\n" +
            "    .controls input[type='range'] { width: 120px; }\n" +
            "    .main { display: flex; height: calc(100vh - 160px); }\n" +

            // 流程图面板
            "    .flowchart-panel { width: 480px; min-width: 480px; background: white; border-right: 1px solid #ddd; overflow-y: auto; position: relative; }\n" +
            "    .flowchart-panel h2 { padding: 12px 15px; background: #34495e; color: white; font-size: 15px; position: sticky; top: 0; z-index: 20; }\n" +
            "    .flowchart { padding: 20px 15px; position: relative; }\n" +
            "    .flow-arrows { position: absolute; top: 0; left: 0; pointer-events: none; z-index: 1; }\n" +
            "    .flow-nodes { display: flex; flex-direction: column; gap: 20px; position: relative; z-index: 2; align-items: center; }\n" +
            "    .flow-layer { display: flex; justify-content: center; gap: 15px; width: 100%; }\n" +

            // 通用节点
            "    @keyframes pulse { 0%,100% { box-shadow: 0 0 0 0 rgba(231,76,60,0.7); } 50% { box-shadow: 0 0 0 10px rgba(231,76,60,0); } }\n" +
            "    .flow-node { padding: 12px 16px; border: 2px solid #3498db; border-radius: 8px; background: white; min-width: 200px; max-width: 420px; text-align: center; transition: all 0.3s; position: relative; }\n" +
            "    .flow-node.active { border-color: #e74c3c; background: #fff3cd; transform: scale(1.06); box-shadow: 0 0 15px rgba(231,76,60,0.7); z-index: 10; animation: pulse 1.2s infinite; }\n" +
            "    .flow-node.visited { border-color: #27ae60; background: #eafaf1; }\n" +
            "    .node-label { font-size: 13px; font-weight: bold; }\n" +
            "    .node-desc { font-size: 11px; color: #666; margin-top: 4px; }\n" +

            // 终端节点
            "    .flow-node-terminal { border-radius: 25px; background: #95a5a6; color: white; border-color: #7f8c8d; min-width: 100px; padding: 8px 20px; }\n" +
            "    .flow-node-terminal.active { background: #e74c3c; }\n" +

            // 组节点
            "    .flow-node-group { border: 3px solid #9b59b6; background: #f5eef8; }\n" +
            "    .flow-node-group.active { border-color: #e74c3c; background: #fff3cd; }\n" +

            // 菱形（clip-path 双层：外框 + 内填）
            "    .dim-outer { width: 170px; height: 100px; background: #e67e22; clip-path: polygon(50% 0%, 100% 50%, 50% 100%, 0% 50%); display: flex; align-items: center; justify-content: center; margin: 0 auto; transition: all 0.3s; }\n" +
            "    .dim-inner { width: 162px; height: 92px; background: #ffeaa7; clip-path: polygon(50% 0%, 100% 50%, 50% 100%, 0% 50%); display: flex; align-items: center; justify-content: center; padding: 0 30px; }\n" +
            "    .dim-text { font-size: 12px; font-weight: bold; color: #2c3e50; text-align: center; line-height: 1.3; }\n" +
            "    .dim-outer.active { background: #e74c3c; transform: scale(1.1); animation: pulse 1.2s infinite; }\n" +
            "    .dim-inner.active { background: #ff7675; }\n" +
            "    .dim-inner.active .dim-text { color: white; }\n" +

            // 循环虚线框
            "    .loop-wrapper { border: 2px dashed #27ae60; border-radius: 12px; padding: 10px 12px 12px; background: rgba(39,174,96,0.04); width: 400px; transition: all 0.3s; }\n" +
            "    .loop-wrapper.active { border-color: #e74c3c; background: rgba(231,76,60,0.05); box-shadow: 0 0 15px rgba(231,76,60,0.3); }\n" +
            "    .loop-wrapper.visited { border-color: #27ae60; }\n" +

            // 循环头部
            "    .loop-header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 6px; margin-bottom: 8px; border-bottom: 1px dashed #27ae60; font-size: 10px; }\n" +
            "    .loop-badge { font-weight: bold; color: white; background: #27ae60; padding: 2px 8px; border-radius: 3px; font-size: 11px; }\n" +
            "    .loop-wrapper.active .loop-badge { background: #e74c3c; }\n" +
            "    .loop-count { font-weight: bold; color: #2c3e50; font-size: 12px; }\n" +
            "    .loop-goal { color: #888; font-style: italic; font-size: 10px; }\n" +

            // 循环子流程图
            "    .loop-flow { display: flex; flex-direction: column; align-items: center; gap: 3px; }\n" +
            "    .lf-step { padding: 5px 12px; border: 2px solid #3498db; border-radius: 5px; background: white; font-size: 11px; text-align: center; transition: all 0.3s; min-width: 110px; }\n" +
            "    .lf-step-title { font-weight: bold; color: #2c3e50; }\n" +
            "    .lf-step-val { font-size: 10px; color: #888; margin-top: 2px; }\n" +
            "    .lf-step.lf-active { border-color: #e74c3c; background: #fff3cd; transform: scale(1.08); box-shadow: 0 0 10px rgba(231,76,60,0.5); }\n" +
            "    .lf-step.lf-done { border-color: #27ae60; background: #eafaf1; }\n" +
            "    .lf-arrow { color: #95a5a6; font-size: 13px; line-height: 1; }\n" +

            // 子菱形
            "    .lf-dim-outer { width: 110px; height: 60px; background: #e67e22; clip-path: polygon(50% 0%, 100% 50%, 50% 100%, 0% 50%); display: flex; align-items: center; justify-content: center; transition: all 0.3s; }\n" +
            "    .lf-dim-inner { width: 104px; height: 54px; background: #ffeaa7; clip-path: polygon(50% 0%, 100% 50%, 50% 100%, 0% 50%); display: flex; align-items: center; justify-content: center; font-size: 10px; font-weight: bold; color: #2c3e50; }\n" +
            "    .lf-dim-outer.lf-active { background: #e74c3c; transform: scale(1.08); }\n" +
            "    .lf-dim-outer.lf-active .lf-dim-inner { background: #ff7675; color: white; }\n" +

            // 分支
            "    .lf-branches { display: flex; gap: 20px; align-items: flex-start; margin: 2px 0; }\n" +
            "    .lf-branch { display: flex; flex-direction: column; align-items: center; gap: 2px; }\n" +
            "    .lf-tag { font-size: 9px; font-weight: bold; padding: 1px 6px; border-radius: 3px; }\n" +
            "    .lf-tag-yes { background: #d5f4e6; color: #27ae60; }\n" +
            "    .lf-tag-no { background: #fdebd0; color: #e67e22; }\n" +
            "    .lf-branch-step { min-width: 95px; font-size: 10px; font-weight: bold; padding: 5px 8px; }\n" +
            "    .lf-step-inc { font-size: 10px; color: #7f8c8d; border-style: dashed; min-width: 90px; }\n" +

            // 进度条
            "    .loop-progress-track { height: 6px; background: #ecf0f1; border-radius: 3px; margin-top: 8px; overflow: hidden; }\n" +
            "    .loop-progress-fill { height: 100%; background: #27ae60; width: 0%; transition: width 0.2s; }\n" +
            "    .loop-wrapper.active .loop-progress-fill { background: #e74c3c; }\n" +

            // 右侧面板
            "    .right-side { flex: 1; display: flex; flex-direction: column; min-width: 0; }\n" +
            "    .steps-panel { height: 45%; border-bottom: 1px solid #ddd; overflow-y: auto; }\n" +
            "    .steps-panel h2 { padding: 12px 15px; background: #34495e; color: white; font-size: 15px; position: sticky; top: 0; }\n" +
            "    .step-list { padding: 8px; }\n" +
            "    .step-item { padding: 5px 8px; margin: 2px 0; background: #f9f9f9; border: 1px solid #e0e0e0; border-radius: 4px; cursor: pointer; display: flex; align-items: center; gap: 8px; transition: all 0.15s; font-size: 12px; }\n" +
            "    .step-item:hover { background: #f0f0f0; }\n" +
            "    .step-item.active { background: #3498db; color: white; border-color: #2980b9; }\n" +
            "    .step-num { font-weight: bold; min-width: 40px; font-size: 11px; }\n" +
            "    .op-name { flex: 1; font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }\n" +
            "    .group-badge { font-size: 9px; padding: 1px 5px; border-radius: 3px; background: #95a5a6; color: white; flex-shrink: 0; }\n" +
            "    .duration { font-size: 10px; color: #888; min-width: 55px; text-align: right; flex-shrink: 0; }\n" +
            "    .step-item.active .duration { color: #ecf0f1; }\n" +
            "    .detail-panel { height: 55%; overflow-y: auto; }\n" +
            "    .detail-panel h2 { padding: 12px 15px; background: #34495e; color: white; font-size: 15px; position: sticky; top: 0; }\n" +
            "    .detail-view { padding: 15px; }\n" +
            "    .placeholder { color: #888; font-style: italic; }\n" +
            "    .detail-section { margin: 12px 0; }\n" +
            "    .detail-section h3 { font-size: 13px; color: #2c3e50; margin-bottom: 6px; border-bottom: 2px solid #3498db; padding-bottom: 3px; }\n" +
            "    .detail-content { background: #f9f9f9; padding: 10px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 11px; line-height: 1.5; }\n" +
            "    .detail-content pre { white-space: pre-wrap; word-wrap: break-word; }\n" +
            "    .group-ecOp { border-left: 3px solid #3498db; }\n" +
            "    .group-mulLoop, .group-mul_kG, .group-mul_sG, .group-mul_tP { border-left: 3px solid #27ae60; }\n" +
            "    .group-sm2Sign { border-left: 3px solid #9b59b6; }\n" +
            "    .group-sm2Verify { border-left: 3px solid #e74c3c; }\n" +
            "    .group-keygen, .group-computeZA, .group-computeE, .group-computeR, .group-computeS, .group-computeT, .group-returnRS { border-left: 3px solid #2980b9; }\n" +
            "    .group-start, .group-end { border-left: 3px solid #7f8c8d; }\n" +
            "    .group-checkR, .group-checkRK, .group-checkFormat, .group-checkT, .group-checkPoint, .group-finalCheck { border-left: 3px solid #e67e22; }\n" +
            "    .group-pad, .group-split, .group-initV, .group-cfLoop, .group-expand, .group-compress, .group-finalize { border-left: 3px solid #16a085; }\n" +
            "    .group-keyExpand, .group-initReg, .group-roundLoop, .group-sBox, .group-linear, .group-reverse { border-left: 3px solid #8e44ad; }\n" +
            "    .group-selectP, .group-selectQ, .group-computeN, .group-computePhi, .group-selectE, .group-computeD, .group-encrypt, .group-decrypt { border-left: 3px solid #c0392b; }\n" +
            "    .group-setup, .group-pairing, .group-sign, .group-verify { border-left: 3px solid #2c3e50; }\n" +
            "    .group-mlkem, .group-mldsa, .group-slhdsa, .group-encap, .group-decap { border-left: 3px solid #d35400; }\n" +
            "    .group-keyDist, .group-partialSign, .group-combine { border-left: 3px solid #27ae60; }\n" +
            "    .group-keyAgg, .group-nonceGen, .group-nonceAgg, .group-partialSig, .group-sigAgg { border-left: 3px solid #2980b9; }\n" +
            "    .group-round1, .group-round2, .group-round3 { border-left: 3px solid #f39c12; }\n";
    }

    private static String getJavaScript(List<TraceEvent> events, FlowDefinition flow)
    {
        StringBuilder js = new StringBuilder();

        js.append("const events = [\n");
        for (int i = 0; i < events.size(); i++)
        {
            TraceEvent event = events.get(i);
            js.append("  {\n");
            js.append("    step: ").append(event.getStepNumber()).append(",\n");
            js.append("    operation: '").append(escapeJs(event.getOperation())).append("',\n");
            js.append("    inputs: ").append(inputsToJson(event.getInputs())).append(",\n");
            js.append("    output: ").append(objectToJson(event.getOutput())).append(",\n");
            js.append("    group: '").append(escapeJs(event.getGroup())).append("',\n");
            js.append("    metadata: ").append(metadataToJson(event.getMetadata())).append(",\n");
            js.append("    duration: ").append(String.format("%.3f", event.getDurationMillis())).append("\n");
            js.append("  }");
            if (i < events.size() - 1)
            {
                js.append(",");
            }
            js.append("\n");
        }
        js.append("];\n\n");

        js.append("const flowEdges = [\n");
        for (FlowEdge edge : flow.getEdges())
        {
            js.append("  {from: '").append(edge.getFromId()).append("', to: '")
                .append(edge.getToId()).append("', label: '").append(escapeJs(edge.getLabel())).append("'},\n");
        }
        js.append("];\n\n");

        // 循环节点全部从 DOM 读取（SM2 标量乘 / SM3 分块与轮 / SM4 轮 / RSA 模幂 …）
        js.append("const LOOP_NODES = Array.from(document.querySelectorAll('.loop-wrapper')).map(el => ({\n");
        js.append("  id: el.dataset.loopId,\n");
        js.append("  group: el.dataset.group,\n");
        js.append("  kind: el.dataset.loopKind,\n");
        js.append("  symbol: el.dataset.loopSymbol || 'k'\n");
        js.append("}));\n");
        js.append("const LOOP_IDS = LOOP_NODES.map(l => l.id);\n");
        js.append("const LOOP_BY_ID = {};\n");
        js.append("LOOP_NODES.forEach(l => { LOOP_BY_ID[l.id] = l; });\n");
        js.append("const LOOP_TOTALS = {};\n");
        js.append("events.forEach(ev => {\n");
        js.append("  const m = ev.metadata;\n");
        js.append("  if (m && m.loopName && LOOP_TOTALS[m.loopName] === undefined) LOOP_TOTALS[m.loopName] = m.loopTotal;\n");
        js.append("});\n\n");

        // SVG defs 常量
        js.append("const SVG_DEFS = `<defs>\n");
        js.append("  <marker id='arrowhead' markerWidth='10' markerHeight='10' refX='9' refY='3' orient='auto'>\n");
        js.append("    <polygon points='0 0, 10 3, 0 6' fill='#3498db' />\n");
        js.append("  </marker>\n");
        js.append("  <marker id='arrowhead-active' markerWidth='10' markerHeight='10' refX='9' refY='3' orient='auto'>\n");
        js.append("    <polygon points='0 0, 10 3, 0 6' fill='#e74c3c' />\n");
        js.append("  </marker>\n");
        js.append("  <marker id='arrowhead-visited' markerWidth='10' markerHeight='10' refX='9' refY='3' orient='auto'>\n");
        js.append("    <polygon points='0 0, 10 3, 0 6' fill='#27ae60' />\n");
        js.append("  </marker>\n");
        js.append("</defs>`;\n\n");

        js.append("let currentStep = 0;\n");
        js.append("let isPlaying = false;\n");
        js.append("let playInterval = null;\n\n");

        js.append("function goToStep(step) {\n");
        js.append("  if (step < 1) step = 1;\n");
        js.append("  if (step > events.length) step = events.length;\n");
        js.append("  currentStep = step;\n");
        js.append("  updateDisplay();\n");
        js.append("}\n\n");

        js.append("function firstStep() { goToStep(1); }\n");
        js.append("function lastStep() { goToStep(events.length); }\n");
        js.append("function prevStep() { goToStep(currentStep - 1); }\n");
        js.append("function nextStep() { goToStep(currentStep + 1); }\n\n");

        js.append("function togglePlay() {\n");
        js.append("  isPlaying = !isPlaying;\n");
        js.append("  document.getElementById('playBtn').textContent = isPlaying ? '⏸' : '▶';\n");
        js.append("  if (isPlaying) {\n");
        js.append("    playInterval = setInterval(() => {\n");
        js.append("      if (currentStep < events.length) { nextStep(); } else { togglePlay(); }\n");
        js.append("    }, document.getElementById('speed').value);\n");
        js.append("  } else { clearInterval(playInterval); }\n");
        js.append("}\n\n");

        js.append("document.getElementById('speed').addEventListener('input', (e) => {\n");
        js.append("  document.getElementById('speedVal').textContent = e.target.value + 'ms';\n");
        js.append("  if (isPlaying) {\n");
        js.append("    clearInterval(playInterval);\n");
        js.append("    playInterval = setInterval(() => {\n");
        js.append("      if (currentStep < events.length) { nextStep(); } else { togglePlay(); }\n");
        js.append("    }, e.target.value);\n");
        js.append("  }\n");
        js.append("});\n\n");

        // 复合分组取基组："mul_kG:ecOp" → "mul_kG"
        js.append("function baseGroup(group) { return group.split(':')[0]; }\n\n");

        js.append("function computeVisitedGroups() {\n");
        js.append("  const groups = new Set();\n");
        js.append("  for (let i = 0; i < currentStep && i < events.length; i++) {\n");
        js.append("    groups.add(baseGroup(events[i].group));\n");
        js.append("  }\n");
        js.append("  return groups;\n");
        js.append("}\n\n");

        // 精确分组（含 "verify1:checkFormat" 这种复合 group），用于逐个子步骤高亮
        js.append("function computeSeenGroups() {\n");
        js.append("  const groups = new Set();\n");
        js.append("  for (let i = 0; i < currentStep && i < events.length; i++) {\n");
        js.append("    groups.add(events[i].group);\n");
        js.append("  }\n");
        js.append("  return groups;\n");
        js.append("}\n\n");

        // 清除所有子流程图高亮
        js.append("function clearLoopFlowActive() {\n");
        js.append("  LOOP_IDS.forEach(id => {\n");
        js.append("    ['lf-extract-','lf-dec-','lf-da-','lf-do-','lf-body-','lf-inc-'].forEach(p => {\n");
        js.append("      const el = document.getElementById(p + id);\n");
        js.append("      if (el) el.classList.remove('lf-active');\n");
        js.append("    });\n");
        js.append("  });\n");
        js.append("}\n\n");

        // 重置所有循环进度（总数取自事件元数据，kG 扫 256 位而 sG/tP 可能是 255 位）
        js.append("function resetLoopProgress() {\n");
        js.append("  LOOP_IDS.forEach(id => {\n");
        js.append("    const count = document.getElementById('loop-count-' + id);\n");
        js.append("    const fill = document.getElementById('progress-' + id);\n");
        js.append("    const bit = document.getElementById('lf-bit-' + id);\n");
        js.append("    const total = LOOP_TOTALS[id];\n");
        js.append("    const meta = LOOP_BY_ID[id] || {kind: 'bit', symbol: 'k'};\n");
        js.append("    if (count) count.textContent = '0 / ' + (total !== undefined ? total : '-');\n");
        js.append("    if (fill) fill.style.width = '0%';\n");
        js.append("    if (bit) bit.textContent = loopValText(meta, '-');\n");
        js.append("  });\n");
        js.append("}\n\n");

        // 循环第一步的数值文本：逐位循环显示 k[j]=1，其余显示 j / N
        js.append("function loopValText(meta, val) {\n");
        js.append("  if (meta.kind === 'bit') return meta.symbol + '[j] = ' + val;\n");
        js.append("  if (meta.kind === 'round') return 'round = ' + val;\n");
        js.append("  if (meta.kind === 'block') return 'item = ' + val;\n");
        js.append("  return 'step = ' + val;\n");
        js.append("}\n\n");

        // 根据事件历史重建所有循环状态（支持后退）：
        // 计数/进度/最后一位对每个循环都恢复，但子流程图的“当前步骤”只高亮 curBase 对应的那个循环，
        // 否则 kG 跑完后停在最后一位的红色高亮会一路带到 sG/tP，看起来像三个循环同时在跑。
        js.append("function updateAllLoops(curBase) {\n");
        js.append("  resetLoopProgress();\n");
        js.append("  clearLoopFlowActive();\n");
        js.append("  let lastLoopEvent = null;\n");
        js.append("  for (let i = 0; i < currentStep && i < events.length; i++) {\n");
        js.append("    const ev = events[i];\n");
        js.append("    if (ev.metadata && ev.metadata.loopName) {\n");
        js.append("      applyLoopState(ev);\n");
        js.append("      lastLoopEvent = ev;\n");
        js.append("    }\n");
        js.append("  }\n");
        // 子流程的当前迭代只高亮“与当前事件同一基组”的那个循环；
        // 旧流程 group 就是 loopName（相等），新流程 group 是 "verify1:mul_sG"（基组相等）。
        js.append("  if (lastLoopEvent && baseGroup(lastLoopEvent.group) === curBase) {\n");
        js.append("    highlightLoopFlow(lastLoopEvent);\n");
        js.append("  }\n");
        js.append("}\n\n");

        // 应用单个循环事件的状态（counter/progress/bit）
        js.append("function applyLoopState(ev) {\n");
        js.append("  const name = ev.metadata.loopName;\n");
        js.append("  const iter = ev.metadata.loopIteration;\n");
        js.append("  const total = ev.metadata.loopTotal;\n");
        js.append("  const count = document.getElementById('loop-count-' + name);\n");
        js.append("  const fill = document.getElementById('progress-' + name);\n");
        js.append("  const bitEl = document.getElementById('lf-bit-' + name);\n");
        js.append("  const meta = LOOP_BY_ID[name] || {kind: 'bit', symbol: 'k'};\n");
        js.append("  if (count) count.textContent = iter + ' / ' + total;\n");
        js.append("  if (fill) fill.style.width = (iter / total * 100).toFixed(1) + '%';\n");
        js.append("  if (bitEl) {\n");
        js.append("    if (meta.kind === 'bit') {\n");
        js.append("      if (ev.inputs && ev.inputs.bitVal !== undefined) {\n");
        js.append("        const bp = ev.inputs.bitPos !== undefined ? ev.inputs.bitPos : '?';\n");
        js.append("        bitEl.textContent = meta.symbol + '[' + bp + '] = ' + ev.inputs.bitVal;\n");
        js.append("      }\n");
        js.append("    } else {\n");
        js.append("      bitEl.textContent = loopValText(meta, iter);\n");
        js.append("    }\n");
        js.append("  }\n");
        js.append("}\n\n");

        // 高亮某个循环子流程图里当前迭代走过的步骤
        js.append("function highlightLoopFlow(ev) {\n");
        js.append("  const name = ev.metadata.loopName;\n");
        js.append("  ['lf-extract-','lf-body-','lf-inc-'].forEach(p => {\n");
        js.append("    const el = document.getElementById(p + name);\n");
        js.append("    if (el) el.classList.add('lf-active');\n");
        js.append("  });\n");
        js.append("  const meta = LOOP_BY_ID[name];\n");
        js.append("  if (!meta || meta.kind !== 'bit') return;\n");
        js.append("  const decEl = document.getElementById('lf-dec-' + name);\n");
        js.append("  if (decEl) decEl.classList.add('lf-active');\n");
        js.append("  const daEl = document.getElementById('lf-da-' + name);\n");
        js.append("  const doEl = document.getElementById('lf-do-' + name);\n");
        js.append("  if (daEl && doEl && ev.inputs && ev.inputs.bitVal !== undefined) {\n");
        js.append("    if (ev.inputs.bitVal === 1) { daEl.classList.add('lf-active'); doEl.classList.remove('lf-active'); }\n");
        js.append("    else { doEl.classList.add('lf-active'); daEl.classList.remove('lf-active'); }\n");
        js.append("  }\n");
        js.append("}\n\n");

        // 活动节点自动滚入流程图视口，避免高亮在屏幕外、看起来像“光标跳到别处”
        js.append("function scrollFlowTo(el) {\n");
        js.append("  if (!el) return;\n");
        js.append("  const panel = document.querySelector('.flowchart-panel');\n");
        js.append("  if (!panel) return;\n");
        js.append("  const pRect = panel.getBoundingClientRect();\n");
        js.append("  const eRect = el.getBoundingClientRect();\n");
        js.append("  const headerH = 48;\n");
        js.append("  if (eRect.top < pRect.top + headerH || eRect.bottom > pRect.bottom) {\n");
        js.append("    panel.scrollTop += (eRect.top - pRect.top) - panel.clientHeight / 2 + eRect.height / 2;\n");
        js.append("  }\n");
        js.append("}\n\n");

        js.append("function updateDisplay() {\n");
        js.append("  document.getElementById('stepInfo').textContent = `Step ${currentStep} / ${events.length}`;\n\n");

        // 步骤列表
        js.append("  document.querySelectorAll('.step-item').forEach(el => {\n");
        js.append("    el.classList.remove('active');\n");
        js.append("    if (parseInt(el.dataset.step) === currentStep) {\n");
        js.append("      el.classList.add('active');\n");
        js.append("      el.scrollIntoView({ block: 'nearest' });\n");
        js.append("    }\n");
        js.append("  });\n\n");

        js.append("  const event = events[currentStep - 1];\n");
        js.append("  if (!event) return;\n\n");

        js.append("  const visitedGroups = computeVisitedGroups();\n");
        js.append("  const seenGroups = computeSeenGroups();\n");
        js.append("  const curBase = baseGroup(event.group);\n\n");

        // 主流程图节点状态（loop-wrapper 也是 flow-node，一起处理）：
        //   精确 group 命中 → 只高亮这一步；无冒号的节点（group/循环/普通节点）再按基组命中。
        //   复合 group 的子步骤不会因为同组其它步骤已出现过就提前变绿。
        js.append("  document.querySelectorAll('.flow-node, .loop-wrapper').forEach(el => {\n");
        js.append("    el.classList.remove('active', 'visited', 'exact');\n");
        js.append("    const g = el.dataset.group;\n");
        js.append("    const isExact = g === event.group;\n");
        js.append("    const isBaseNode = g.indexOf(':') < 0 && g === curBase;\n");
        js.append("    const wasSeen = seenGroups.has(g) || (g.indexOf(':') < 0 && visitedGroups.has(g));\n");
        js.append("    if (wasSeen) el.classList.add('visited');\n");
        js.append("    if (isExact || isBaseNode) {\n");
        js.append("      el.classList.add('active');\n");
        js.append("      el.classList.remove('visited');\n");
        js.append("      if (isExact) el.classList.add('exact');\n");
        js.append("    }\n");
        js.append("  });\n\n");

        // 菱形 active 类同步到内外层
        js.append("  document.querySelectorAll('.dim-outer').forEach(el => {\n");
        js.append("    el.classList.remove('active');\n");
        js.append("    const inner = el.querySelector('.dim-inner');\n");
        js.append("    if (inner) inner.classList.remove('active');\n");
        js.append("  });\n");
        js.append("  const activeNode = document.querySelector('.flow-node.active');\n");
        js.append("  if (activeNode) {\n");
        js.append("    const outer = activeNode.querySelector('.dim-outer');\n");
        js.append("    if (outer) {\n");
        js.append("      outer.classList.add('active');\n");
        js.append("      const inner = outer.querySelector('.dim-inner');\n");
        js.append("      if (inner) inner.classList.add('active');\n");
        js.append("    }\n");
        js.append("  }\n\n");

        // 循环状态
        js.append("  updateAllLoops(curBase);\n\n");

        // 活动节点（含循环框）滚入视口：优先滚动到精确命中的子步骤，避免停在组标题上
        js.append("  const activeEl = document.querySelector('.flow-node.exact, .loop-wrapper.exact') ||\n");
        js.append("    document.querySelector('.flow-node.active, .loop-wrapper.active');\n");
        js.append("  scrollFlowTo(activeEl);\n\n");

        // 箭头
        js.append("  updateArrows(visitedGroups, curBase);\n\n");

        // 详情
        js.append("  let html = '<div class=\"detail-section\"><h3>Operation</h3><div class=\"detail-content\"><pre>' + event.operation + '</pre></div></div>';\n");
        js.append("  html += '<div class=\"detail-section\"><h3>Group</h3><div class=\"detail-content\"><pre>' + event.group + '</pre></div></div>';\n");
        js.append("  html += '<div class=\"detail-section\"><h3>Inputs</h3><div class=\"detail-content\">';\n");
        js.append("  for (const [key, value] of Object.entries(event.inputs)) {\n");
        js.append("    html += `<div><strong>${key}:</strong> <pre>${formatValue(value)}</pre></div>`;\n");
        js.append("  }\n");
        js.append("  html += '</div></div>';\n");
        js.append("  html += '<div class=\"detail-section\"><h3>Output</h3><div class=\"detail-content\"><pre>' + formatValue(event.output) + '</pre></div></div>';\n");
        js.append("  if (event.metadata && Object.keys(event.metadata).length > 0) {\n");
        js.append("    html += '<div class=\"detail-section\"><h3>Metadata</h3><div class=\"detail-content\"><pre>' + JSON.stringify(event.metadata, null, 2) + '</pre></div></div>';\n");
        js.append("  }\n");
        js.append("  html += '<div class=\"detail-section\"><h3>Duration</h3><div class=\"detail-content\"><pre>' + event.duration + ' ms</pre></div></div>';\n");
        js.append("  document.getElementById('detailView').innerHTML = html;\n");
        js.append("}\n\n");

        // 箭头绘制：from/to 用节点 id，visited 判定用 data-group
        js.append("function updateArrows(visitedGroups, curBase) {\n");
        js.append("  const svg = document.getElementById('flowArrows');\n");
        js.append("  const container = document.getElementById('flowchart');\n");
        js.append("  svg.innerHTML = SVG_DEFS;\n");
        js.append("  svg.setAttribute('width', container.scrollWidth);\n");
        js.append("  svg.setAttribute('height', container.scrollHeight);\n\n");

        js.append("  flowEdges.forEach(edge => {\n");
        js.append("    const fromNode = document.getElementById('flow-' + edge.from);\n");
        js.append("    const toNode = document.getElementById('flow-' + edge.to);\n");
        js.append("    if (!fromNode || !toNode) return;\n\n");

        js.append("    const cRect = container.getBoundingClientRect();\n");
        js.append("    const fRect = fromNode.getBoundingClientRect();\n");
        js.append("    const tRect = toNode.getBoundingClientRect();\n\n");

        js.append("    const x1 = fRect.left + fRect.width / 2 - cRect.left;\n");
        js.append("    const y1 = fRect.bottom - cRect.top;\n");
        js.append("    const x2 = tRect.left + tRect.width / 2 - cRect.left;\n");
        js.append("    const y2 = tRect.top - cRect.top;\n\n");

        js.append("    const fromVisited = visitedGroups.has(fromNode.dataset.group);\n");
        js.append("    const toVisited = visitedGroups.has(toNode.dataset.group);\n");
        js.append("    const edgeVisited = fromVisited && toVisited;\n");
        js.append("    const isCurrent = curBase === fromNode.dataset.group || curBase === toNode.dataset.group;\n\n");

        js.append("    let color, markerRef, opacity, width;\n");
        js.append("    if (isCurrent) {\n");
        js.append("      color = '#e74c3c'; markerRef = 'url(#arrowhead-active)'; opacity = 1; width = 2.5;\n");
        js.append("    } else if (edgeVisited) {\n");
        js.append("      color = '#27ae60'; markerRef = 'url(#arrowhead-visited)'; opacity = 0.8; width = 2;\n");
        js.append("    } else {\n");
        js.append("      color = '#bdc3c7'; markerRef = 'url(#arrowhead)'; opacity = 0.3; width = 1.5;\n");
        js.append("    }\n\n");

        js.append("    const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');\n");
        js.append("    line.setAttribute('x1', x1); line.setAttribute('y1', y1);\n");
        js.append("    line.setAttribute('x2', x2); line.setAttribute('y2', y2);\n");
        js.append("    line.setAttribute('stroke', color);\n");
        js.append("    line.setAttribute('stroke-width', width);\n");
        js.append("    line.setAttribute('marker-end', markerRef);\n");
        js.append("    line.setAttribute('opacity', opacity);\n");
        js.append("    svg.appendChild(line);\n\n");

        js.append("    if (edge.label) {\n");
        js.append("      const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');\n");
        js.append("      text.setAttribute('x', (x1 + x2) / 2 + 8);\n");
        js.append("      text.setAttribute('y', (y1 + y2) / 2);\n");
        js.append("      text.setAttribute('fill', isCurrent ? '#e74c3c' : (edgeVisited ? '#27ae60' : '#95a5a6'));\n");
        js.append("      text.setAttribute('font-size', '10');\n");
        js.append("      text.setAttribute('font-weight', 'bold');\n");
        js.append("      text.textContent = edge.label;\n");
        js.append("      svg.appendChild(text);\n");
        js.append("    }\n");
        js.append("  });\n");
        js.append("}\n\n");

        js.append("function formatValue(val) {\n");
        js.append("  if (val === null || val === undefined) return 'null';\n");
        js.append("  if (typeof val === 'string') return val;\n");
        js.append("  if (Array.isArray(val)) return val.join(', ');\n");
        js.append("  if (typeof val === 'object') return JSON.stringify(val, null, 2);\n");
        js.append("  return String(val);\n");
        js.append("}\n\n");

        js.append("if (events.length > 0) {\n");
        js.append("  goToStep(1);\n");
        js.append("  window.addEventListener('resize', () => updateDisplay());\n");
        js.append("}\n");

        return js.toString();
    }

    private static String inputsToJson(Map<String, Object> inputs)
    {
        StringBuilder json = new StringBuilder("{");
        int i = 0;
        for (Map.Entry<String, Object> entry : inputs.entrySet())
        {
            if (i > 0)
            {
                json.append(", ");
            }
            json.append("'").append(escapeJs(entry.getKey())).append("': ");
            json.append(objectToJson(entry.getValue()));
            i++;
        }
        json.append("}");
        return json.toString();
    }

    private static String metadataToJson(Map<String, Object> metadata)
    {
        if (metadata == null || metadata.isEmpty())
        {
            return "{}";
        }
        StringBuilder json = new StringBuilder("{");
        int i = 0;
        for (Map.Entry<String, Object> entry : metadata.entrySet())
        {
            if (i > 0)
            {
                json.append(", ");
            }
            json.append("'").append(escapeJs(entry.getKey())).append("': ");
            Object value = entry.getValue();
            if (value instanceof Number || value instanceof Boolean)
            {
                json.append(value);
            }
            else
            {
                json.append("'").append(escapeJs(value.toString())).append("'");
            }
            i++;
        }
        json.append("}");
        return json.toString();
    }

    private static String objectToJson(Object obj)
    {
        if (obj == null)
        {
            return "null";
        }
        if (obj instanceof BigInteger)
        {
            return "'" + obj.toString() + "'";
        }
        if (obj instanceof byte[])
        {
            byte[] bytes = (byte[])obj;
            return "'" + bytesToHex(bytes) + "'";
        }
        if (obj instanceof BigInteger[])
        {
            BigInteger[] arr = (BigInteger[])obj;
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < arr.length; i++)
            {
                if (i > 0)
                {
                    sb.append(", ");
                }
                sb.append("'").append(arr[i].toString()).append("'");
            }
            sb.append("]");
            return sb.toString();
        }
        if (obj instanceof Object[])
        {
            Object[] arr = (Object[])obj;
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < arr.length; i++)
            {
                if (i > 0)
                {
                    sb.append(", ");
                }
                sb.append(objectToJson(arr[i]));
            }
            sb.append("]");
            return sb.toString();
        }
        if (obj instanceof Number)
        {
            return obj.toString();
        }
        return "'" + escapeJs(obj.toString()) + "'";
    }

    private static String bytesToHex(byte[] bytes)
    {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes)
        {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static String escapeHtml(String s)
    {
        return s.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#39;");
    }

    private static String escapeJs(String s)
    {
        return s.replace("\\", "\\\\")
            .replace("'", "\\'")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t");
    }
}
