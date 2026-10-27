# Tracer 实现总结

## 完成的工作

### 1. 架构扩展
- **TraceExecution 注解**：添加 `algorithm()` 属性支持多算法路由
- **Tracer.enable(algorithm)**：支持传入算法名称
- **TraceContext**：存储 algorithm 字段
- **HtmlGenerator**：根据 algorithm 路由到不同的 buildXxxFlow() 方法
- **renderFlowchart**：从硬编码 SM2 层改为动态生成

### 2. 流程图定义
为 9 种算法添加了流程图定义：
- SM2（签名验签）- 21 个节点，含 3 个循环子流程
- SM3（哈希）- 9 个节点
- SM4（分组密码）- 8 个节点
- RSA（公钥密码）- 11 个节点
- SM9（标识密码）- 9 个节点
- PQC（后量子密码）- 8 个节点
- THRESHOLD（门限签名）- 7 个节点
- MULTISIG（多重签名）- 8 个节点
- INTERACTIVE（交互式协同签名）- 8 个节点

### 3. CSS 样式扩展
为新算法的所有 group 添加了颜色标识：
- SM3: pad, split, initV, cfLoop, expand, compress, finalize
- SM4: keyExpand, initReg, roundLoop, sBox, linear, reverse
- RSA: selectP, selectQ, computeN, computePhi, selectE, computeD, encrypt, decrypt
- SM9: setup, pairing, sign, verify
- PQC: mlkem, mldsa, slhdsa, encap, decap
- THRESHOLD: keyDist, partialSign, combine
- MULTISIG: keyAgg, nonceGen, nonceAgg, partialSig, sigAgg
- INTERACTIVE: round1, round2, round3

### 4. 测试文件修改
全部 17 个 essence 测试文件都已添加 Tracer 支持：

| 文件 | @TraceExecution | Tracer.trace | @Rule |
|------|----------------|--------------|-------|
| Sm2EssenceTest.java | 2 | 25 | ✓ |
| Sm3EssenceTest.java | 1 | 9 | ✓ |
| Sm4EssenceTest.java | 1 | 9 | ✓ |
| RsaEssenceTest.java | 1 | 19 | ✓ |
| Sm9KeyEssenceTest.java | 1 | 5 | ✓ |
| Sm9PairingEssenceTest.java | 1 | 4 | ✓ |
| Sm9SignEssenceTest.java | 1 | 6 | ✓ |
| Sm9EncryptEssenceTest.java | 1 | 6 | ✓ |
| Sm9ExchangeEssenceTest.java | 1 | 6 | ✓ |
| PqcEssenceTest.java | 3 | 13 | ✓ |
| MlKemQuantumAnalysisTest.java | 2 | 7 | ✓ |
| MlDsaQuantumAnalysisTest.java | 3 | 9 | ✓ |
| SlhDsaEssenceTest.java | 3 | 10 | ✓ |
| QuantumResistanceAnalysisTest.java | 1 | 5 | ✓ |
| ThresholdEssenceTest.java | 1 | 7 | ✓ |
| MultisigEssenceTest.java | 1 | 8 | ✓ |
| InteractiveCollaborativeSignatureEssenceTest.java | 1 | 8 | ✓ |

### 5. 验证结果
- ✅ 编译成功（learning:compileJava, learning:compileTestJava）
- ✅ SM2 测试通过，生成 1.8M HTML
- ✅ SM3 测试通过，生成 31K HTML
- ✅ RSA 测试通过，生成 HTML
- ✅ 所有 17 个文件都有完整的 Tracer 支持

## 使用方式

在测试方法上添加注解：
```java
@TraceExecution(value = "算法描述", algorithm = "SM2")
@Test
public void testMethod() {
    Tracer.trace("start", new Object[]{"input", value}, null, "start");
    // ... 算法步骤 ...
    Tracer.trace("step1", new Object[]{"param", param}, result, "step1");
    // ... 更多步骤 ...
    Tracer.trace("end", new Object[]{"result", "pass"}, null, "end");
}
```

运行测试后，HTML 可视化文件自动生成在 `learning/build/traces/` 目录。

## 文件清单

### 核心框架（7 个文件）
- learning/src/main/java/org/bouncycastle/learning/trace/Tracer.java
- learning/src/main/java/org/bouncycastle/learning/trace/TraceEvent.java
- learning/src/main/java/org/bouncycastle/learning/trace/TraceContext.java
- learning/src/main/java/org/bouncycastle/learning/trace/HtmlGenerator.java
- learning/src/main/java/org/bouncycastle/learning/trace/FlowDefinition.java
- learning/src/main/java/org/bouncycastle/learning/trace/FlowNode.java
- learning/src/main/java/org/bouncycastle/learning/trace/FlowEdge.java

### 测试注解与规则（2 个文件）
- learning/src/test/java/org/bouncycastle/learning/trace/TraceExecution.java
- learning/src/test/java/org/bouncycastle/learning/trace/TraceExecutionRule.java

### 测试文件（17 个文件）
所有 learning/src/test/java/org/bouncycastle/learning/essence/*.java 文件

## 下一步
运行完整测试套件生成所有算法的 HTML 可视化：
```bash
./gradlew :learning:test --tests "*EssenceTest" --tests "*QuantumAnalysisTest"
```

生成的 HTML 文件在 `learning/build/traces/` 目录，可用浏览器打开查看流程追踪可视化。
