package org.bouncycastle.learning.trace;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 主题流程图注册表 —— 按测试主题选择流程图，而不是按算法一刀切。
 *
 * <p>每个测试方法通过 {@code @TraceExecution(flow = "...")} 指定 key；事件的 group
 * 必须等于流程节点的 group，否则光标无处可跳（HtmlGenerator 会打印警告）。
 *
 * <p>命名约定：节点 id 与 group 相同；循环节点的 id 同时是事件 metadata 里的 loopName。
 */
public final class Flows
{
    private static final Map<String, FlowDefinition> REGISTRY = new LinkedHashMap<>();

    static
    {
        register("SM2-CORE", sm2Core());
        register("SM2-SIGNVERIFY", sm2SignVerify());
        register("SM2-CURVE", sm2Curve());
        register("SM2-CIPHER", sm2Cipher());
        register("SM2-KREUSE", sm2KReuse());

        register("SM3-HASH", sm3Hash());
        register("SM3-HMAC", sm3Hmac());
        register("SM3-KDF", sm3Kdf());
        register("SM3-BOOL", sm3Bool());

        register("SM4-CORE", sm4Core());
        register("SM4-MODES", sm4Modes());
        register("SM4-GCM", sm4Gcm());
        register("SM4-PAD", sm4Pad());

        register("RSA-CORE", rsaCore());
        register("RSA-ATTACK", rsaAttack());
        register("RSA-PADDING", rsaPadding());
        register("RSA-BLOCKS", rsaBlocks());

        register("SM9-KEY", sm9Key());
        register("SM9-PAIRING", sm9Pairing());
        register("SM9-SIGN", sm9Sign());
        register("SM9-ENCRYPT", sm9Encrypt());
        register("SM9-EXCHANGE", sm9Exchange());

        register("PQC-MLKEM", pqcMlKem());
        register("PQC-PUBKEY", pqcPublicKey());
        register("PQC-MLDSA", pqcMlDsa());
        register("PQC-SLHDSA", pqcSlhDsa());
        register("PQC-MATH", pqcMath());
        register("PQC-QUANTUM", pqcQuantum());

        register("THRESHOLD-ECDSA", thresholdEcdsa());
        register("THRESHOLD-SHAMIR", thresholdShamir());
        register("MULTISIG-CORE", multisigCore());
        register("INTERACTIVE-CORE", interactiveCore());
    }

    private Flows()
    {
    }

    public static FlowDefinition resolve(String flowKey)
    {
        if (flowKey == null || flowKey.isEmpty())
        {
            return null;
        }
        return REGISTRY.get(flowKey);
    }

    private static void register(String key, FlowDefinition flow)
    {
        REGISTRY.put(key, flow);
    }

    private static FlowNode node(FlowDefinition flow, String id, String label, FlowNodeType type,
        String desc)
    {
        return flow.addNode(id, label, type, id, desc);
    }

    private static FlowNode loop(FlowDefinition flow, String id, String label, FlowLoopKind kind,
        String symbol, String stepLabel, String desc)
    {
        return flow.addNode(id, label, FlowNodeType.LOOP, id, desc)
            .asLoop(kind, symbol, stepLabel);
    }

    /** 节点 id 与 group 不同的情况（如 verify1_mul_sG 属于 verify1:mul_sG）。 */
    private static FlowNode nodeIn(FlowDefinition flow, String id, String group, String label,
        FlowNodeType type, String desc)
    {
        return flow.addNode(id, label, type, group, desc);
    }

    private static void chain(FlowDefinition flow, String... ids)
    {
        for (int i = 0; i + 1 < ids.length; i++)
        {
            flow.addEdge(ids[i], ids[i + 1]);
        }
    }

    // ------------------------------------------------------------------ SM2

    private static FlowDefinition sm2Core()
    {
        FlowDefinition flow = new FlowDefinition("SM2 签名验签");

        node(flow, "start", "开始", FlowNodeType.TERMINAL, "");
        node(flow, "keygen", "生成密钥对 (d, P=dG)", FlowNodeType.OPERATION, "私钥 d，公钥 P");
        node(flow, "computeZA", "计算 ZA = SM3(ENTL||ID||a||b||Gx||Gy||Px||Py)", FlowNodeType.OPERATION, "身份哈希");
        node(flow, "computeE", "计算 e = SM3(ZA||M)", FlowNodeType.OPERATION, "消息哈希");
        node(flow, "sm2Sign", "SM2 签名", FlowNodeType.GROUP, "签名整体流程");
        loop(flow, "mul_kG", "k·G 标量乘", FlowLoopKind.BIT, "k", null, "double-and-add：逐位扫描 k");
        node(flow, "computeR", "r = (e + x₁) mod n", FlowNodeType.OPERATION, "计算 r");
        node(flow, "checkR", "r == 0 ?", FlowNodeType.DECISION, "判断 r");
        node(flow, "computeS", "s = (k - rd)(1+d)⁻¹ mod n", FlowNodeType.OPERATION, "计算 s");
        node(flow, "checkRK", "r + k ≡ 0 (mod n) ?", FlowNodeType.DECISION, "判断 r+k");
        node(flow, "returnRS", "返回 (r, s)", FlowNodeType.OPERATION, "签名结果");
        node(flow, "sm2Verify", "SM2 验签", FlowNodeType.GROUP, "验签整体流程");
        node(flow, "checkFormat", "r,s ∈ [1,n-1] ?", FlowNodeType.DECISION, "格式检查");
        node(flow, "computeT", "t = (r + s) mod n", FlowNodeType.OPERATION, "计算 t");
        node(flow, "checkT", "t == 0 ?", FlowNodeType.DECISION, "判断 t");
        loop(flow, "mul_sG", "s·G 标量乘", FlowLoopKind.BIT, "s", null, "double-and-add：逐位扫描 s");
        loop(flow, "mul_tP", "t·P 标量乘", FlowLoopKind.BIT, "t", null, "double-and-add：逐位扫描 t");
        node(flow, "ecOp", "(x₁,y₁) = sG + tP", FlowNodeType.OPERATION, "点加");
        node(flow, "checkPoint", "point == O ?", FlowNodeType.DECISION, "判断点");
        node(flow, "finalCheck", "(e + x₁) mod n == r ?", FlowNodeType.DECISION, "最终核对");
        node(flow, "end", "结束", FlowNodeType.TERMINAL, "");

        chain(flow, "start", "keygen", "computeZA", "computeE", "sm2Sign", "mul_kG", "computeR",
            "checkR", "computeS", "checkRK", "returnRS", "sm2Verify", "checkFormat", "computeT",
            "checkT", "mul_sG", "mul_tP", "ecOp", "checkPoint", "finalCheck", "end");
        flow.addEdge("checkR", "computeS", "r≠0");
        flow.addEdge("checkRK", "returnRS", "r+k≠0");
        flow.addEdge("checkFormat", "computeT", "合法");
        flow.addEdge("checkT", "mul_sG", "t≠0");
        flow.addEdge("checkPoint", "finalCheck", "非无穷远");
        flow.addEdge("finalCheck", "end", "相等");
        flow.setStartNodeId("start");
        return flow;
    }

    /**
     * 签名验签完整流程：我们的签名、BC 交叉验证，以及<b>三次独立的验签</b>
     * （合法签名 / 篡改 r / 篡改消息），每次验签都有自己的节点区块与用途标签。
     */
    private static FlowDefinition sm2SignVerify()
    {
        FlowDefinition flow = new FlowDefinition("SM2 签名验签（三次验签展开）");

        node(flow, "start", "开始", FlowNodeType.TERMINAL, "");
        node(flow, "keygen", "生成密钥对 (d, P=dG)", FlowNodeType.OPERATION, "私钥 d，公钥 P");
        node(flow, "computeZA", "计算 ZA = SM3(ENTL||ID||a||b||Gx||Gy||Px||Py)", FlowNodeType.OPERATION, "身份哈希");
        node(flow, "computeE", "计算 e = SM3(ZA||M)", FlowNodeType.OPERATION, "消息哈希");
        node(flow, "sm2Sign", "我们的签名 sm2Sign(d, e, k)", FlowNodeType.GROUP,
            "r = (e+x₁) mod n；s = (k−rd)(1+d)⁻¹ mod n");
        loop(flow, "mul_kG", "k·G 标量乘", FlowLoopKind.BIT, "k", null, "double-and-add：逐位扫描 k");
        node(flow, "computeR", "r = (e + x₁) mod n", FlowNodeType.OPERATION, "");
        node(flow, "checkR", "r == 0 ?", FlowNodeType.DECISION, "为 0 必须换 k 重签");
        node(flow, "computeS", "s = (k - rd)(1+d)⁻¹ mod n", FlowNodeType.OPERATION, "");
        node(flow, "checkRK", "r + k ≡ 0 (mod n) ?", FlowNodeType.DECISION, "退化则换 k");
        node(flow, "returnRS", "返回 (r, s)", FlowNodeType.OPERATION, "我们的签名结果");
        node(flow, "bcVerify", "BC 验我们的签名 (SM3withSM2.verify)", FlowNodeType.OPERATION,
            "交叉验证：应通过");
        node(flow, "bcSign", "BC 用同一私钥签名 (SM3withSM2.sign)", FlowNodeType.OPERATION,
            "得到 DER(r,s)，供下面三次验签使用");

        verifyPhase(flow, "verify1", "验签① 合法签名：BC 签 → 我们验",
            "原样 (r,s) 与 e，期望 true", "期望 true：签名合法");
        verifyPhase(flow, "verify2", "验签② 篡改 r：r ← r+1",
            "同一签名，只把 r 加 1，期望 false", "期望 false：核对式不成立");
        // 验签③ 的前置一步：篡改后的消息要先重新哈希出 e′，它不属于 sm2Verify 内部，
        // 但必须落在 verify3 区块里，否则光标会跳回主流程开头的 computeE
        nodeIn(flow, "verify3_hashM", "verify3:hashM", "计算 e′ = SM3(ZA‖M′)",
            FlowNodeType.OPERATION, "篡改消息的摘要");
        verifyPhase(flow, "verify3", "验签③ 篡改消息：e ← SM3(ZA‖M′)",
            "同一 (r,s)，换成另一条消息的 e，期望 false", "期望 false：e 与 x₁ 对不上");

        node(flow, "end", "结束", FlowNodeType.TERMINAL, "");

        chain(flow, "start", "keygen", "computeZA", "computeE", "sm2Sign", "mul_kG", "computeR",
            "checkR", "computeS", "checkRK", "returnRS", "bcVerify", "bcSign", "verify1");
        flow.addEdge("checkR", "computeS", "r≠0");
        flow.addEdge("checkRK", "returnRS", "r+k≠0");

        flow.addEdge("verify1_finalCheck", "verify2", "通过 → 继续");
        flow.addEdge("verify2_finalCheck", "verify3_hashM", "拒绝 → 继续");
        flow.addEdge("verify3_hashM", "verify3", "换消息 M′ 求新 e");
        flow.addEdge("verify3_finalCheck", "end", "拒绝（三条断言全部成立）");

        flow.setStartNodeId("start");
        return flow;
    }

    /** 一次 sm2Verify 调用的完整子流程：enter → 格式 → t → sG → tP → 点加 → 点检查 → 最终核对。 */
    private static void verifyPhase(FlowDefinition flow, String prefix, String label,
        String enterDesc, String finalDesc)
    {
        node(flow, prefix, label, FlowNodeType.GROUP, "sm2Verify(pub, e, rs)");
        nodeIn(flow, prefix + "_enter", prefix + ":sm2Verify", "进入 sm2Verify(pub, e, rs)",
            FlowNodeType.OPERATION, enterDesc);
        nodeIn(flow, prefix + "_checkFormat", prefix + ":checkFormat", "r,s ∈ [1,n-1] ?",
            FlowNodeType.DECISION, "格式检查");
        nodeIn(flow, prefix + "_computeT", prefix + ":computeT", "t = (r + s) mod n",
            FlowNodeType.OPERATION, "");
        nodeIn(flow, prefix + "_checkT", prefix + ":checkT", "t == 0 ?", FlowNodeType.DECISION, "");
        flow.addNode(prefix + "_mul_sG", "s·G 标量乘", FlowNodeType.LOOP, prefix + ":mul_sG",
            "double-and-add：逐位扫描 s").asLoop(FlowLoopKind.BIT, "s", null);
        flow.addNode(prefix + "_mul_tP", "t·P 标量乘", FlowNodeType.LOOP, prefix + ":mul_tP",
            "double-and-add：逐位扫描 t").asLoop(FlowLoopKind.BIT, "t", null);
        nodeIn(flow, prefix + "_ecOp", prefix + ":ecOp", "(x₁,y₁) = sG + tP",
            FlowNodeType.OPERATION, "点加");
        nodeIn(flow, prefix + "_checkPoint", prefix + ":checkPoint", "point == O ?",
            FlowNodeType.DECISION, "");
        nodeIn(flow, prefix + "_finalCheck", prefix + ":finalCheck", "(e + x₁) mod n == r ?",
            FlowNodeType.DECISION, finalDesc);

        chain(flow, prefix, prefix + "_enter", prefix + "_checkFormat", prefix + "_computeT",
            prefix + "_checkT", prefix + "_mul_sG", prefix + "_mul_tP", prefix + "_ecOp",
            prefix + "_checkPoint", prefix + "_finalCheck");
        flow.addEdge(prefix + "_checkFormat", prefix + "_computeT", "合法");
        flow.addEdge(prefix + "_checkT", prefix + "_mul_sG", "t≠0");
        flow.addEdge(prefix + "_checkPoint", prefix + "_finalCheck", "非无穷远");
    }

    private static FlowDefinition sm2Curve()
    {
        FlowDefinition flow = new FlowDefinition("SM2 曲线与点运算");

        node(flow, "start", "开始", FlowNodeType.TERMINAL, "");
        node(flow, "params", "曲线参数 (p, a, b, n, G)", FlowNodeType.OPERATION, "sm2p256v1");
        node(flow, "keygen", "密钥对 d → P = dG", FlowNodeType.OPERATION, "私钥与公钥");
        node(flow, "ecAdd", "点加 P + Q", FlowNodeType.OPERATION, "弦斜率公式");
        node(flow, "ecDouble", "倍点 2P", FlowNodeType.OPERATION, "切线斜率公式");
        node(flow, "onCurve", "点在曲线上? y² ≡ x³+ax+b", FlowNodeType.DECISION, "曲线方程校验");
        loop(flow, "scalarMul", "标量乘 k·P", FlowLoopKind.BIT, "k", null, "double-and-add");
        node(flow, "serialize", "点编码 / 与 BC 比对", FlowNodeType.OPERATION, "坐标还原");
        node(flow, "end", "结束", FlowNodeType.TERMINAL, "");

        chain(flow, "start", "params", "keygen", "ecAdd", "ecDouble", "onCurve", "scalarMul",
            "serialize", "end");
        flow.addEdge("scalarMul", "ecAdd", "每次迭代");
        flow.setStartNodeId("start");
        return flow;
    }

    private static FlowDefinition sm2Cipher()
    {
        FlowDefinition flow = new FlowDefinition("SM2 公钥加密");

        node(flow, "start", "开始", FlowNodeType.TERMINAL, "");
        node(flow, "keygen", "接收方密钥对 (d, P)", FlowNodeType.OPERATION, "解密私钥");
        node(flow, "c1", "C1 = k·G", FlowNodeType.OPERATION, "临时公钥点");
        node(flow, "kdf", "t = KDF(x₂‖y₂, klen)", FlowNodeType.OPERATION, "密钥流");
        node(flow, "c2", "C2 = M ⊕ t", FlowNodeType.OPERATION, "异或加密");
        node(flow, "c3", "C3 = SM3(x₂‖M‖y₂)", FlowNodeType.OPERATION, "完整性校验");
        node(flow, "decrypt", "M' = C2 ⊕ KDF(d·C1)", FlowNodeType.OPERATION, "解密");
        node(flow, "compare", "M' == M ?", FlowNodeType.DECISION, "往返一致");
        node(flow, "end", "结束", FlowNodeType.TERMINAL, "");

        chain(flow, "start", "keygen", "c1", "kdf", "c2", "c3", "decrypt", "compare", "end");
        flow.addEdge("compare", "end", "相等");
        flow.setStartNodeId("start");
        return flow;
    }

    private static FlowDefinition sm2KReuse()
    {
        FlowDefinition flow = new FlowDefinition("SM2 随机数复用攻击");

        node(flow, "start", "开始", FlowNodeType.TERMINAL, "");
        node(flow, "collect", "收集签名 (r, s₁) / (r, s₂)", FlowNodeType.OPERATION, "同一 k 产生相同 r");
        node(flow, "solve", "联立方程解出 k", FlowNodeType.OPERATION, "s₁ − s₂ 消去 d");
        node(flow, "recover", "d = (s·k − e)·r⁻¹ mod n", FlowNodeType.OPERATION, "恢复私钥");
        node(flow, "verify", "恢复的 d 能重签?", FlowNodeType.DECISION, "有效性验证");
        node(flow, "exploit", "枚举 / 线性方程 / 偏差统计", FlowNodeType.OPERATION, "弱随机源利用");
        node(flow, "end", "结束", FlowNodeType.TERMINAL, "");

        chain(flow, "start", "collect", "solve", "recover", "verify", "exploit", "end");
        flow.addEdge("verify", "exploit", "是");
        flow.setStartNodeId("start");
        return flow;
    }

    // ------------------------------------------------------------------ SM3

    private static FlowDefinition sm3Hash()
    {
        FlowDefinition flow = new FlowDefinition("SM3 哈希");

        node(flow, "start", "开始", FlowNodeType.TERMINAL, "");
        node(flow, "pad", "MD 填充: m‖0x80‖0^k‖len₆₄", FlowNodeType.OPERATION, "补到 64 字节倍数");
        node(flow, "split", "切分为 64 字节块", FlowNodeType.OPERATION, "B₀..Bₙ₋₁");
        node(flow, "initV", "V₀ = IV (8 个初始链接字)", FlowNodeType.OPERATION, "A..H 初值");
        loop(flow, "cfLoop", "压缩函数循环", FlowLoopKind.BLOCK, "", "压缩一块",
            "Vᵢ = CF(Vᵢ₋₁, Bᵢ)");
        node(flow, "expand", "W 扩展: W₀..W₆₇", FlowNodeType.OPERATION, "消息扩展");
        loop(flow, "compress", "64 轮压缩", FlowLoopKind.ROUND, "j", "FF/GG/P0/P1 轮函数",
            "每轮更新 A..H");
        node(flow, "finalize", "输出 Vₙ = A..H → 32 字节", FlowNodeType.OPERATION, "大端序列化");
        node(flow, "end", "结束", FlowNodeType.TERMINAL, "");

        chain(flow, "start", "pad", "split", "initV", "cfLoop", "expand", "compress", "finalize", "end");
        flow.addEdge("compress", "cfLoop", "下一块");
        flow.setStartNodeId("start");
        return flow;
    }

    private static FlowDefinition sm3Hmac()
    {
        FlowDefinition flow = new FlowDefinition("SM3-HMAC");

        node(flow, "start", "开始", FlowNodeType.TERMINAL, "");
        node(flow, "fitKey", "密钥规约: key → K (64 字节)", FlowNodeType.OPERATION, "过长先哈希、过短补零");
        node(flow, "ipad", "K ⊕ ipad (0x36…)", FlowNodeType.OPERATION, "内层掩码");
        node(flow, "inner", "inner = SM3((K⊕ipad)‖m)", FlowNodeType.OPERATION, "内层摘要");
        node(flow, "opad", "K ⊕ opad (0x5c…)", FlowNodeType.OPERATION, "外层掩码");
        node(flow, "outer", "SM3((K⊕opad)‖inner)", FlowNodeType.OPERATION, "外层摘要");
        node(flow, "compare", "与 BC HMac 一致?", FlowNodeType.DECISION, "交叉验证");
        node(flow, "end", "结束", FlowNodeType.TERMINAL, "");

        chain(flow, "start", "fitKey", "ipad", "inner", "opad", "outer", "compare", "end");
        flow.addEdge("compare", "end", "相等");
        flow.setStartNodeId("start");
        return flow;
    }

    private static FlowDefinition sm3Kdf()
    {
        FlowDefinition flow = new FlowDefinition("SM3-KDF 计数器模式");

        node(flow, "start", "开始", FlowNodeType.TERMINAL, "");
        node(flow, "init", "ct = 1，blocks = ⌈klen/32⌉", FlowNodeType.OPERATION, "初始化计数器");
        loop(flow, "ctLoop", "计数器循环", FlowLoopKind.ROUND, "ct", "SM3(z‖ct₄)",
            "每段 32 字节");
        node(flow, "hash", "SM3(z‖ct₄)", FlowNodeType.OPERATION, "一段密钥流");
        node(flow, "concat", "stream ‖= 段", FlowNodeType.OPERATION, "拼接");
        node(flow, "truncate", "截断到 klen 字节", FlowNodeType.OPERATION, "取前 klen 字节");
        node(flow, "compare", "与 BC KDF2 一致?", FlowNodeType.DECISION, "交叉验证");
        node(flow, "end", "结束", FlowNodeType.TERMINAL, "");

        chain(flow, "start", "init", "ctLoop", "hash", "concat", "truncate", "compare", "end");
        flow.addEdge("concat", "ctLoop", "ct++");
        flow.addEdge("compare", "end", "相等");
        flow.setStartNodeId("start");
        return flow;
    }

    private static FlowDefinition sm3Bool()
    {
        FlowDefinition flow = new FlowDefinition("SM3 布尔函数");

        node(flow, "start", "开始", FlowNodeType.TERMINAL, "");
        node(flow, "ff", "FF_j: 前 16 轮异或 / 后 48 轮多数", FlowNodeType.OPERATION, "线性 → 非线性");
        node(flow, "gg", "GG_j: 前 16 轮异或 / 后 48 轮选择", FlowNodeType.OPERATION, "选择函数");
        node(flow, "p0p1", "P0/P1 扩散 (rotl ⊕ rotl ⊕ x)", FlowNodeType.OPERATION, "单比特雪崩");
        node(flow, "tconst", "轮常数 T_j (两个值)", FlowNodeType.OPERATION, "j<16 / j≥16");
        node(flow, "assert", "性质断言全部通过?", FlowNodeType.DECISION, "分解式核对");
        node(flow, "end", "结束", FlowNodeType.TERMINAL, "");

        chain(flow, "start", "ff", "gg", "p0p1", "tconst", "assert", "end");
        flow.addEdge("assert", "end", "是");
        flow.setStartNodeId("start");
        return flow;
    }

    // ------------------------------------------------------------------ SM4

    private static FlowDefinition sm4Core()
    {
        FlowDefinition flow = new FlowDefinition("SM4 分组密码核心");

        node(flow, "start", "开始", FlowNodeType.TERMINAL, "");
        node(flow, "keyExpand", "密钥扩展: MK → rk₀..rk₃₁", FlowNodeType.OPERATION, "T 变换 + CK");
        node(flow, "initReg", "初始化 (X₀,X₁,X₂,X₃)", FlowNodeType.OPERATION, "128-bit 分块");
        loop(flow, "roundLoop", "32 轮迭代", FlowLoopKind.ROUND, "i",
            "Xᵢ₊₄ = Xᵢ ⊕ T(Xᵢ₊₁⊕Xᵢ₊₂⊕Xᵢ₊₃⊕rkᵢ)", "轮函数 T = τ + L");
        node(flow, "sBox", "S 盒替换 (τ)", FlowNodeType.OPERATION, "非线性层");
        node(flow, "linear", "线性变换 L", FlowNodeType.OPERATION,
            "⊕ rotl(·,2) ⊕ rotl(·,10) ⊕ rotl(·,18) ⊕ rotl(·,24)");
        node(flow, "reverse", "反序变换 (X₃₅,X₃₄,X₃₃,X₃₂)", FlowNodeType.OPERATION, "Y = (Y₀,Y₁,Y₂,Y₃)");
        node(flow, "end", "结束", FlowNodeType.TERMINAL, "");

        chain(flow, "start", "keyExpand", "initReg", "roundLoop", "sBox", "linear", "reverse", "end");
        flow.addEdge("linear", "roundLoop", "下一轮");
        flow.setStartNodeId("start");
        return flow;
    }

    private static FlowDefinition sm4Modes()
    {
        FlowDefinition flow = new FlowDefinition("SM4 分组模式");

        node(flow, "start", "开始", FlowNodeType.TERMINAL, "");
        node(flow, "pad", "消息填充 / 分块", FlowNodeType.OPERATION, "PKCS#7");
        node(flow, "iv", "初始化向量 IV", FlowNodeType.OPERATION, "CBC/CFB/OFB 起点");
        loop(flow, "blockLoop", "逐块处理", FlowLoopKind.BLOCK, "", "处理一块", "模式决定块间关系");
        node(flow, "encBlock", "E_K(X) 分组加密", FlowNodeType.OPERATION, "32 轮核心");
        node(flow, "xor", "C = P ⊕ 输入", FlowNodeType.OPERATION, "异或组合");
        node(flow, "feedback", "反馈 / 链接", FlowNodeType.OPERATION, "CBC 用密文、CFB/OFB 用输出");
        node(flow, "final", "拼接输出 / 去填充", FlowNodeType.OPERATION, "结果");
        node(flow, "compare", "与 BC 一致?", FlowNodeType.DECISION, "交叉验证");
        node(flow, "end", "结束", FlowNodeType.TERMINAL, "");

        chain(flow, "start", "pad", "iv", "blockLoop", "encBlock", "xor", "feedback", "final",
            "compare", "end");
        flow.addEdge("feedback", "blockLoop", "下一块");
        flow.addEdge("compare", "end", "相等");
        flow.setStartNodeId("start");
        return flow;
    }

    private static FlowDefinition sm4Gcm()
    {
        FlowDefinition flow = new FlowDefinition("SM4-GCM");

        node(flow, "start", "开始", FlowNodeType.TERMINAL, "");
        node(flow, "ctr", "CTR 模式加密", FlowNodeType.OPERATION, "计数器分组");
        node(flow, "ghash", "GHASH: GF(2¹²⁸) 乘法", FlowNodeType.OPERATION, "认证");
        node(flow, "tag", "T = E_K(J₀) ⊕ S", FlowNodeType.OPERATION, "认证标签");
        node(flow, "verify", "标签校验通过?", FlowNodeType.DECISION, "篡改检测");
        node(flow, "end", "结束", FlowNodeType.TERMINAL, "");

        chain(flow, "start", "ctr", "ghash", "tag", "verify", "end");
        flow.addEdge("verify", "end", "通过");
        flow.setStartNodeId("start");
        return flow;
    }

    private static FlowDefinition sm4Pad()
    {
        FlowDefinition flow = new FlowDefinition("SM4 填充正交性");

        node(flow, "start", "开始", FlowNodeType.TERMINAL, "");
        node(flow, "pad", "PKCS#7 填充", FlowNodeType.OPERATION, "补 n 个 0x0n");
        node(flow, "encrypt", "分组加密", FlowNodeType.OPERATION, "填充与模式无关");
        node(flow, "decrypt", "分组解密", FlowNodeType.OPERATION, "逆运算");
        node(flow, "unpad", "去除填充", FlowNodeType.OPERATION, "检查填充字节");
        node(flow, "compare", "m' == m ?", FlowNodeType.DECISION, "往返一致");
        node(flow, "end", "结束", FlowNodeType.TERMINAL, "");

        chain(flow, "start", "pad", "encrypt", "decrypt", "unpad", "compare", "end");
        flow.addEdge("compare", "end", "相等");
        flow.setStartNodeId("start");
        return flow;
    }

    // ------------------------------------------------------------------ RSA

    private static FlowDefinition rsaCore()
    {
        FlowDefinition flow = new FlowDefinition("RSA 密钥与模幂");

        node(flow, "start", "开始", FlowNodeType.TERMINAL, "");
        node(flow, "selectP", "选取大素数 p", FlowNodeType.OPERATION, "随机 + 素性检测");
        node(flow, "selectQ", "选取大素数 q", FlowNodeType.OPERATION, "随机 + 素性检测");
        node(flow, "computeN", "n = p·q", FlowNodeType.OPERATION, "模数");
        node(flow, "computePhi", "λ = lcm(p−1, q−1)", FlowNodeType.OPERATION, "Carmichael 函数");
        node(flow, "selectE", "选取 e: gcd(e, λ)=1", FlowNodeType.OPERATION, "通常 65537");
        node(flow, "computeD", "d = e⁻¹ mod λ", FlowNodeType.OPERATION, "扩展欧几里得");
        node(flow, "keygen", "组装九元组 (n,e,d,λ,dp,dq,qInv,p,q)", FlowNodeType.OPERATION, "密钥无对象");
        loop(flow, "encrypt", "加密: c = mᵉ mod n", FlowLoopKind.BIT, "e", null, "平方-乘");
        loop(flow, "decrypt", "解密: m = cᵈ mod n", FlowLoopKind.BIT, "d", null, "平方-乘 / CRT");
        node(flow, "end", "结束", FlowNodeType.TERMINAL, "");

        chain(flow, "start", "selectP", "selectQ", "computeN", "computePhi", "selectE",
            "computeD", "keygen", "encrypt", "decrypt", "end");
        flow.addEdge("decrypt", "encrypt", "下一组明文");
        flow.setStartNodeId("start");
        return flow;
    }

    private static FlowDefinition rsaAttack()
    {
        FlowDefinition flow = new FlowDefinition("RSA 教科书攻击");

        node(flow, "start", "开始", FlowNodeType.TERMINAL, "");
        node(flow, "keygen", "已知公钥 (n, e)", FlowNodeType.OPERATION, "攻击者视角");
        node(flow, "encrypt", "截获密文 c = mᵉ mod n", FlowNodeType.OPERATION, "确定性加密");
        node(flow, "guess", "构造 c′ = c·yᵉ / 枚举固定点", FlowNodeType.OPERATION, "无填充的弱点");
        node(flow, "decrypt", "被诱导解密 c′：得到 m·y", FlowNodeType.OPERATION, "乘法同态 oracle");
        node(flow, "root", "整数开方 m = c^(1/e)", FlowNodeType.OPERATION, "mᵉ < n 时无需模");
        node(flow, "compare", "恢复的 m 与原文一致?", FlowNodeType.DECISION, "攻击成立");
        node(flow, "end", "结束", FlowNodeType.TERMINAL, "");

        chain(flow, "start", "keygen", "encrypt", "guess", "decrypt", "root", "compare", "end");
        flow.addEdge("compare", "end", "是");
        flow.setStartNodeId("start");
        return flow;
    }

    private static FlowDefinition rsaPadding()
    {
        FlowDefinition flow = new FlowDefinition("RSA 填充方案");

        node(flow, "start", "开始", FlowNodeType.TERMINAL, "");
        node(flow, "mgf1", "MGF1: hash(seed‖counter)", FlowNodeType.OPERATION, "掩码生成函数");
        node(flow, "encode", "编码 (v1.5 / OAEP / PSS)", FlowNodeType.OPERATION, "EM 结构");
        node(flow, "selfCheck", "编码自校验 (PSS)", FlowNodeType.OPERATION, "pssVerify / 确定性");
        node(flow, "modExp", "模幂 (RSA 原语)", FlowNodeType.OPERATION, "填充与原语正交");
        node(flow, "decode", "解码 / 还原", FlowNodeType.OPERATION, "分离字段");
        node(flow, "verify", "字段校验通过?", FlowNodeType.DECISION, "填充检查");
        node(flow, "end", "结束", FlowNodeType.TERMINAL, "");

        chain(flow, "start", "mgf1", "encode", "selfCheck", "modExp", "decode", "verify", "end");
        flow.addEdge("verify", "end", "通过");
        flow.setStartNodeId("start");
        return flow;
    }

    private static FlowDefinition rsaBlocks()
    {
        FlowDefinition flow = new FlowDefinition("RSA 分块加密");

        node(flow, "start", "开始", FlowNodeType.TERMINAL, "");
        node(flow, "split", "按 k−11 字节分块", FlowNodeType.OPERATION, "长消息切块");
        loop(flow, "blockLoop", "逐块 RSA", FlowLoopKind.BLOCK, "", "对一块做模幂", "每块独立加密");
        node(flow, "modExp", "cᵢ = mᵢᵉ mod n", FlowNodeType.OPERATION, "原语");
        node(flow, "concat", "拼接密文块", FlowNodeType.OPERATION, "按序拼接");
        node(flow, "compare", "解密还原原文?", FlowNodeType.DECISION, "往返一致");
        node(flow, "end", "结束", FlowNodeType.TERMINAL, "");

        chain(flow, "start", "split", "blockLoop", "modExp", "concat", "compare", "end");
        flow.addEdge("modExp", "blockLoop", "下一块");
        flow.addEdge("compare", "end", "是");
        flow.setStartNodeId("start");
        return flow;
    }

    // ------------------------------------------------------------------ SM9

    private static FlowDefinition sm9Key()
    {
        FlowDefinition flow = new FlowDefinition("SM9 密钥生成");

        node(flow, "start", "开始", FlowNodeType.TERMINAL, "");
        node(flow, "setup", "系统设置: 主密钥 ks / 主公钥 Ppub", FlowNodeType.OPERATION, "KGC");
        node(flow, "keygen", "用户私钥 dA = f(ks, IDA)", FlowNodeType.OPERATION, "基于身份");
        node(flow, "marshal", "DER 编码私钥 / 公钥", FlowNodeType.OPERATION, "序列化");
        node(flow, "unmarshal", "DER 解码还原", FlowNodeType.OPERATION, "反序列化");
        node(flow, "sign", "用生成的密钥签名验签", FlowNodeType.OPERATION, "端到端");
        node(flow, "compare", "密钥与数据一致?", FlowNodeType.DECISION, "编码往返");
        node(flow, "end", "结束", FlowNodeType.TERMINAL, "");

        chain(flow, "start", "setup", "keygen", "marshal", "unmarshal", "sign", "compare", "end");
        flow.addEdge("compare", "end", "一致");
        flow.setStartNodeId("start");
        return flow;
    }

    private static FlowDefinition sm9Pairing()
    {
        FlowDefinition flow = new FlowDefinition("SM9 双线性对");

        node(flow, "start", "开始", FlowNodeType.TERMINAL, "");
        node(flow, "generators", "生成元在曲线 / 阶为 n", FlowNodeType.OPERATION, "G1、G2");
        node(flow, "tower", "扩域塔 Fp → Fp2 → Fp4 → Fp12", FlowNodeType.OPERATION, "运算规则");
        node(flow, "frobenius", "Frobenius 映射 π", FlowNodeType.OPERATION, "特征 p 幂");
        node(flow, "pairing", "R-ate 配对 e(P,Q)", FlowNodeType.OPERATION, "Miller 循环");
        node(flow, "bilinear", "双线性 / 非退化", FlowNodeType.DECISION, "e(aP,bQ)=e(P,Q)^ab");
        node(flow, "encode", "点编码往返", FlowNodeType.OPERATION, "GmSSL 顺序");
        node(flow, "end", "结束", FlowNodeType.TERMINAL, "");

        chain(flow, "start", "generators", "tower", "frobenius", "pairing", "bilinear", "encode", "end");
        flow.addEdge("bilinear", "encode", "成立");
        flow.setStartNodeId("start");
        return flow;
    }

    private static FlowDefinition sm9Sign()
    {
        FlowDefinition flow = new FlowDefinition("SM9 签名验签");

        node(flow, "start", "开始", FlowNodeType.TERMINAL, "");
        node(flow, "keygen", "用户私钥提取 dA", FlowNodeType.OPERATION, "H1(IDA‖hid)");
        node(flow, "hash1", "h = H1(ID‖hid) → 范围内", FlowNodeType.OPERATION, "身份哈希");
        node(flow, "genK", "随机 k ∈ [1,n−1]", FlowNodeType.OPERATION, "一次性随机数");
        node(flow, "pointMul", "w = g^k", FlowNodeType.OPERATION, "G2 上的幂");
        node(flow, "hash2", "h = H2(M‖w)", FlowNodeType.OPERATION, "挑战");
        node(flow, "computeS", "s = (k − h·ks)·(h+ks)⁻¹ 形式", FlowNodeType.OPERATION, "签名值");
        node(flow, "verify", "验签等式成立?", FlowNodeType.DECISION, "配对验证");
        node(flow, "compare", "签名 / DER 编码一致?", FlowNodeType.DECISION, "交叉验证");
        node(flow, "end", "结束", FlowNodeType.TERMINAL, "");

        chain(flow, "start", "keygen", "hash1", "genK", "pointMul", "hash2", "computeS",
            "verify", "compare", "end");
        flow.addEdge("verify", "compare", "通过");
        flow.addEdge("compare", "end", "一致");
        flow.setStartNodeId("start");
        return flow;
    }

    private static FlowDefinition sm9Encrypt()
    {
        FlowDefinition flow = new FlowDefinition("SM9 加密解密");

        node(flow, "start", "开始", FlowNodeType.TERMINAL, "");
        node(flow, "keygen", "接收方私钥 dB", FlowNodeType.OPERATION, "KGC 提取");
        node(flow, "genR", "随机 r ∈ [1,n−1]", FlowNodeType.OPERATION, "一次性随机数");
        node(flow, "pointMul", "C1 = r·Q", FlowNodeType.OPERATION, "G1 上的点");
        node(flow, "w", "w = g^r", FlowNodeType.OPERATION, "共享值");
        node(flow, "kdf", "K = KDF(C1‖w‖IDB, klen)", FlowNodeType.OPERATION, "密钥流");
        node(flow, "c2", "C2 = M ⊕ K1", FlowNodeType.OPERATION, "异或加密");
        node(flow, "c3", "C3 = MAC(K2, M)", FlowNodeType.OPERATION, "完整性");
        node(flow, "decrypt", "解密并验证 C3", FlowNodeType.OPERATION, "接收方");
        node(flow, "compare", "M' == M ?", FlowNodeType.DECISION, "往返一致");
        node(flow, "end", "结束", FlowNodeType.TERMINAL, "");

        chain(flow, "start", "keygen", "genR", "pointMul", "w", "kdf", "c2", "c3",
            "decrypt", "compare", "end");
        flow.addEdge("compare", "end", "相等");
        flow.setStartNodeId("start");
        return flow;
    }

    private static FlowDefinition sm9Exchange()
    {
        FlowDefinition flow = new FlowDefinition("SM9 密钥交换");

        node(flow, "start", "开始", FlowNodeType.TERMINAL, "");
        node(flow, "params", "双方私钥与公开参数", FlowNodeType.OPERATION, "初始化");
        node(flow, "genR", "临时随机 rA / rB", FlowNodeType.OPERATION, "一次性");
        node(flow, "pointMul", "RA = rA·P, RB = rB·P", FlowNodeType.OPERATION, "临时公钥");
        node(flow, "derive", "共享密钥 K = KDF(…) ", FlowNodeType.OPERATION, "双线性对消去");
        node(flow, "confirm", "S1 / S2 确认标签", FlowNodeType.DECISION, "密钥确认");
        node(flow, "tamper", "篡改点后密钥分裂", FlowNodeType.OPERATION, "攻击演示");
        node(flow, "end", "结束", FlowNodeType.TERMINAL, "");

        chain(flow, "start", "params", "genR", "pointMul", "derive", "confirm", "tamper", "end");
        flow.addEdge("confirm", "tamper", "一致");
        flow.setStartNodeId("start");
        return flow;
    }

    // ------------------------------------------------------------------ PQC

    private static FlowDefinition pqcMlKem()
    {
        FlowDefinition flow = new FlowDefinition("ML-KEM 密钥封装");

        node(flow, "start", "开始", FlowNodeType.TERMINAL, "");
        node(flow, "params", "参数表与编码约定：k, dᵤ, dᵥ / compress / 12-bit 打包", FlowNodeType.OPERATION, "长度算术");
        node(flow, "keygen", "KeyGen: (pk, sk)", FlowNodeType.OPERATION, "矩阵 A + 噪声");
        node(flow, "encap", "Encaps(pk) → (c, K)", FlowNodeType.OPERATION, "压缩系数");
        node(flow, "decap", "Decaps(sk, c) → K'", FlowNodeType.OPERATION, "去压缩 + 纠错");
        node(flow, "compare", "K == K' ?", FlowNodeType.DECISION, "隐式拒绝");
        node(flow, "end", "结束", FlowNodeType.TERMINAL, "");

        chain(flow, "start", "params", "keygen", "encap", "decap", "compare", "end");
        flow.addEdge("compare", "end", "相等");
        flow.setStartNodeId("start");
        return flow;
    }

    /**
     * ML-DSA 公钥的分解：t = t1·2^d + t0，公钥只发 ρ 与高位 t1。
     * 节点顺序就是测试里逐步验证的顺序：先拿 BC 密钥，再逐项验证打包/偏置/可逆性。
     */
    private static FlowDefinition pqcPublicKey()
    {
        FlowDefinition flow = new FlowDefinition("ML-DSA 公钥 = ρ ‖ 高位 t1");

        node(flow, "start", "开始", FlowNodeType.TERMINAL, "");
        node(flow, "keygen", "BC 生成 ML-DSA 密钥 (ρ, t1, t0)", FlowNodeType.OPERATION, "种子决定");
        node(flow, "t1-pack", "pack(t1): 每系数 10 bit", FlowNodeType.OPERATION, "320 字节/项");
        node(flow, "unpack-t1", "unpack(t1) 后重新打包", FlowNodeType.OPERATION, "逐字节往返");
        node(flow, "t0-bias", "t0 = 2^12 − a0 的偏置编码", FlowNodeType.OPERATION, "13 bit/项");
        node(flow, "reconstruct-t", "t = t1·2^13 + t0 (mod q)", FlowNodeType.OPERATION, "分解恒等式");
        node(flow, "highBits", "power2Round(t) 还原 (t1, t0)", FlowNodeType.DECISION, "全 256 系数可逆");
        node(flow, "pk-encoded", "pk = ρ ‖ pack(t1)", FlowNodeType.OPERATION, "32 + k·320");
        node(flow, "compare", "编码长度 / 内容一致?", FlowNodeType.DECISION, "交叉验证");
        node(flow, "end", "结束", FlowNodeType.TERMINAL, "");

        chain(flow, "start", "keygen", "t1-pack", "unpack-t1", "t0-bias", "reconstruct-t",
            "highBits", "pk-encoded", "compare", "end");
        flow.addEdge("compare", "end", "一致");
        flow.setStartNodeId("start");
        return flow;
    }

    private static FlowDefinition pqcMlDsa()
    {
        FlowDefinition flow = new FlowDefinition("ML-DSA 签名");

        node(flow, "start", "开始", FlowNodeType.TERMINAL, "");
        node(flow, "keygen", "KeyGen: (pk, sk) 由种子决定", FlowNodeType.OPERATION, "确定性");
        node(flow, "sign", "Sign(sk, M) → σ", FlowNodeType.OPERATION, "拒绝采样");
        node(flow, "verify", "Verify(pk, M, σ)", FlowNodeType.OPERATION, "范数检查");
        node(flow, "reject", "篡改 / 越界被拒绝?", FlowNodeType.DECISION, "拒绝行为");
        node(flow, "compare", "与 BC 实现一致?", FlowNodeType.DECISION, "交叉验证");
        node(flow, "end", "结束", FlowNodeType.TERMINAL, "");

        chain(flow, "start", "keygen", "sign", "verify", "reject", "compare", "end");
        flow.addEdge("reject", "compare", "符合预期");
        flow.addEdge("compare", "end", "一致");
        flow.setStartNodeId("start");
        return flow;
    }

    private static FlowDefinition pqcSlhDsa()
    {
        FlowDefinition flow = new FlowDefinition("SLH-DSA 哈希签名");

        node(flow, "start", "开始", FlowNodeType.TERMINAL, "");
        node(flow, "wots", "WOTS+ 一次性签名链", FlowNodeType.OPERATION, "哈希链");
        node(flow, "fors", "FORS 树", FlowNodeType.OPERATION, "少量次签名");
        node(flow, "xmss", "XMSS 树", FlowNodeType.OPERATION, "Merkle 认证路径");
        node(flow, "hypertree", "超树分层", FlowNodeType.OPERATION, "多层 XMSS");
        node(flow, "security", "量子抗性论证", FlowNodeType.DECISION, "只依赖哈希");
        node(flow, "compare", "与 BC SLH-DSA 一致?", FlowNodeType.DECISION, "交叉验证");
        node(flow, "end", "结束", FlowNodeType.TERMINAL, "");

        chain(flow, "start", "wots", "fors", "xmss", "hypertree", "security", "compare", "end");
        flow.addEdge("security", "compare", "成立");
        flow.addEdge("compare", "end", "一致");
        flow.setStartNodeId("start");
        return flow;
    }

    private static FlowDefinition pqcMath()
    {
        FlowDefinition flow = new FlowDefinition("PQC 数学结构");

        node(flow, "start", "开始", FlowNodeType.TERMINAL, "");
        node(flow, "ring", "环元素 = 系数向量 / 负循环卷积", FlowNodeType.OPERATION, "R_q = Z_q[X]/(Xⁿ+1)");
        node(flow, "ntt", "NTT: 卷积 → 逐点乘", FlowNodeType.OPERATION, "换基");
        node(flow, "moduli", "模数 q 与 2n 次单位根", FlowNodeType.OPERATION, "NTT 存在条件");
        node(flow, "sampling", "拒绝采样 / 二项分布", FlowNodeType.OPERATION, "噪声");
        node(flow, "encoding", "压缩与编码", FlowNodeType.OPERATION, "密文长度");
        node(flow, "params", "参数表", FlowNodeType.OPERATION, "安全等级");
        node(flow, "end", "结束", FlowNodeType.TERMINAL, "");

        chain(flow, "start", "ring", "ntt", "moduli", "sampling", "encoding", "params", "end");
        flow.setStartNodeId("start");
        return flow;
    }

    private static FlowDefinition pqcQuantum()
    {
        FlowDefinition flow = new FlowDefinition("后量子安全性分析");

        node(flow, "start", "开始", FlowNodeType.TERMINAL, "");
        node(flow, "shor", "Shor: 分解 / 离散对数", FlowNodeType.OPERATION, "多项式时间");
        node(flow, "grover", "Grover: 平方加速", FlowNodeType.OPERATION, "暴力搜索减半");
        node(flow, "lattice", "格问题: 无已知量子加速", FlowNodeType.OPERATION, "SIS / LWE");
        node(flow, "compare", "经典 vs 后量子对比", FlowNodeType.OPERATION, "安全假设");
        node(flow, "params", "参数选择 (NIST 等级)", FlowNodeType.DECISION, "安全裕度");
        node(flow, "end", "结束", FlowNodeType.TERMINAL, "");

        chain(flow, "start", "shor", "grover", "lattice", "compare", "params", "end");
        flow.addEdge("compare", "params", "结论");
        flow.setStartNodeId("start");
        return flow;
    }

    // ------------------------------------------------------------------ 协议类

    private static FlowDefinition thresholdEcdsa()
    {
        FlowDefinition flow = new FlowDefinition("门限签名 (t,n)");

        node(flow, "start", "开始", FlowNodeType.TERMINAL, "");
        node(flow, "setup", "系统初始化: 生成 (t,n) 门限参数", FlowNodeType.OPERATION, "Shamir 秘密共享");
        node(flow, "keyDist", "密钥分发: 每个参与者获得份额", FlowNodeType.OPERATION, "si = f(i)");
        loop(flow, "partialSign", "部分签名", FlowLoopKind.BLOCK, "", "参与者生成 σᵢ", "t 个参与者");
        node(flow, "combine", "签名合成: Lagrange 插值", FlowNodeType.OPERATION, "σ = Σ λᵢ·σᵢ");
        node(flow, "verify", "验签: 验证合成签名", FlowNodeType.DECISION, "标准验签算法");
        node(flow, "end", "结束", FlowNodeType.TERMINAL, "");

        chain(flow, "start", "setup", "keyDist", "partialSign", "combine", "verify", "end");
        flow.addEdge("verify", "end", "通过");
        flow.setStartNodeId("start");
        return flow;
    }

    private static FlowDefinition thresholdShamir()
    {
        FlowDefinition flow = new FlowDefinition("Shamir 秘密共享");

        node(flow, "start", "开始", FlowNodeType.TERMINAL, "");
        node(flow, "split", "构造 t−1 次多项式 f(x)", FlowNodeType.OPERATION, "f(0) = 秘密");
        node(flow, "distribute", "分发份额 (xi, f(xi))", FlowNodeType.OPERATION, "n 个参与者");
        node(flow, "recover", "Lagrange 插值求 f(0)", FlowNodeType.OPERATION, "t 个份额");
        node(flow, "verify", "重建的秘密正确?", FlowNodeType.DECISION, "恢复验证");
        node(flow, "security", "t−1 个份额信息论安全", FlowNodeType.OPERATION, "无额外信息");
        node(flow, "end", "结束", FlowNodeType.TERMINAL, "");

        chain(flow, "start", "split", "distribute", "recover", "verify", "security", "end");
        flow.addEdge("verify", "security", "正确");
        flow.setStartNodeId("start");
        return flow;
    }

    private static FlowDefinition multisigCore()
    {
        FlowDefinition flow = new FlowDefinition("多重签名");

        node(flow, "start", "开始", FlowNodeType.TERMINAL, "");
        node(flow, "keyAgg", "密钥聚合: P = Σ Pᵢ", FlowNodeType.OPERATION, "公钥聚合");
        loop(flow, "nonceGen", "nonce 生成", FlowLoopKind.BLOCK, "", "每个参与者生成 Rᵢ", "随机数");
        node(flow, "nonceAgg", "nonce 聚合: R = Σ Rᵢ", FlowNodeType.OPERATION, "聚合 nonce");
        loop(flow, "partialSig", "部分签名", FlowLoopKind.BLOCK, "", "参与者生成 sᵢ", "本地计算");
        node(flow, "sigAgg", "签名聚合: s = Σ sᵢ", FlowNodeType.OPERATION, "聚合签名");
        node(flow, "verify", "验签: (R,s) 对聚合公钥 P", FlowNodeType.DECISION, "标准验签");
        node(flow, "end", "结束", FlowNodeType.TERMINAL, "");

        chain(flow, "start", "keyAgg", "nonceGen", "nonceAgg", "partialSig", "sigAgg", "verify", "end");
        flow.addEdge("verify", "end", "通过");
        flow.setStartNodeId("start");
        return flow;
    }

    private static FlowDefinition interactiveCore()
    {
        FlowDefinition flow = new FlowDefinition("交互式协同签名");

        node(flow, "start", "开始", FlowNodeType.TERMINAL, "");
        node(flow, "setup", "系统初始化", FlowNodeType.OPERATION, "参数生成");
        node(flow, "round1", "轮次 1: 承诺交换", FlowNodeType.OPERATION, "commitment");
        node(flow, "round2", "轮次 2: 挑战生成", FlowNodeType.OPERATION, "challenge");
        node(flow, "round3", "轮次 3: 响应交换", FlowNodeType.OPERATION, "response");
        node(flow, "combine", "签名合成", FlowNodeType.OPERATION, "最终签名");
        node(flow, "verify", "验签", FlowNodeType.DECISION, "验证签名");
        node(flow, "end", "结束", FlowNodeType.TERMINAL, "");

        chain(flow, "start", "setup", "round1", "round2", "round3", "combine", "verify", "end");
        flow.addEdge("verify", "end", "通过");
        flow.setStartNodeId("start");
        return flow;
    }
}
