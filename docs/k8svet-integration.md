# K8sVet 統合ガイド

ComplianceVet を K8sVet に組み込む際の実装ガイドです。

## 統合アーキテクチャ

```
k8svet scan --compliance cis
      │
      ▼
┌─────────────────────────────────────────────────────────┐
│  K8sVet Engine                                          │
│                                                         │
│  1. ManifestVet → []Violation                          │
│  2. RBACVet     → []Violation                          │
│  3. ComplianceVet (このパッケージ)                       │
│     └─ checker.Run(objects, cfg) → []CheckResult        │
│                                                         │
│  4. 結果をマージしてレポート生成                           │
└─────────────────────────────────────────────────────────┘
```

## パッケージのインポート

```go
import (
    // コアパッケージ
    "github.com/ComplianceVet/compliancevet/internal/checker"
    "github.com/ComplianceVet/compliancevet/internal/cluster"
    "github.com/ComplianceVet/compliancevet/internal/parser"
    "github.com/ComplianceVet/compliancevet/internal/report"
    "github.com/ComplianceVet/compliancevet/internal/rules"
    "github.com/ComplianceVet/compliancevet/internal/scanner"
    "github.com/ComplianceVet/compliancevet/internal/scorer"

    // 評価したいセクションを blank import で登録
    // CIS Benchmark
    _ "github.com/ComplianceVet/compliancevet/internal/rules/section1" // Control Plane
    _ "github.com/ComplianceVet/compliancevet/internal/rules/section2" // etcd
    _ "github.com/ComplianceVet/compliancevet/internal/rules/section3" // Worker Nodes
    _ "github.com/ComplianceVet/compliancevet/internal/rules/section4" // Policies
    // NSA/CISA
    _ "github.com/ComplianceVet/compliancevet/internal/rules/section5"
    // PCI-DSS
    _ "github.com/ComplianceVet/compliancevet/internal/rules/section6"
)
```

## ユースケース別実装例

### 1. `k8svet scan --compliance cis` — マニフェストファイルから CIS スコア表示

```go
package compliance

import (
    "fmt"
    "github.com/ComplianceVet/compliancevet/internal/checker"
    "github.com/ComplianceVet/compliancevet/internal/rules"
    "github.com/ComplianceVet/compliancevet/internal/scanner"
    "github.com/ComplianceVet/compliancevet/internal/scorer"

    _ "github.com/ComplianceVet/compliancevet/internal/rules/section1"
    _ "github.com/ComplianceVet/compliancevet/internal/rules/section2"
    _ "github.com/ComplianceVet/compliancevet/internal/rules/section3"
    _ "github.com/ComplianceVet/compliancevet/internal/rules/section4"
)

// CISResult は k8svet のスキャン結果に付加するコンプライアンス情報。
type CISResult struct {
    Score    scorer.OverallScore
    Results  []rules.CheckResult
}

func RunCISScan(paths []string) (*CISResult, error) {
    objects, _, err := scanner.Scan(scanner.ScanOptions{
        Paths:     paths,
        Recursive: true,
    })
    if err != nil {
        return nil, err
    }

    results := checker.Run(objects, checker.Config{
        // CIS セクションのみ
        Sections: []rules.CISSection{
            rules.SectionControlPlane,
            rules.SectionEtcd,
            rules.SectionWorkerNodes,
            rules.SectionPolicies,
        },
    })

    return &CISResult{
        Score:   scorer.Compute(results),
        Results: results,
    }, nil
}

// PrintSummary は k8svet のスキャン出力に1行追加する形式。
func (r *CISResult) PrintSummary() {
    pass, fail, warn := countByStatus(r.Results)
    fmt.Printf("[ComplianceVet]  CIS v1.9  Score: %.0f/100  (%d PASS, %d FAIL, %d WARN)\n",
        r.Score.Score, pass, fail, warn)
    if r.Score.CriticalFail > 0 {
        fmt.Printf("                 ⚠ Critical failures: %d\n", r.Score.CriticalFail)
    }
}

func countByStatus(results []rules.CheckResult) (pass, fail, warn int) {
    for _, r := range results {
        switch r.Status {
        case rules.StatusPass: pass++
        case rules.StatusFail: fail++
        case rules.StatusWarn: warn++
        }
    }
    return
}
```

### 2. `k8svet scan --cluster --compliance cis` — ライブクラスターの評価

```go
package compliance

import (
    "context"
    "time"

    "github.com/ComplianceVet/compliancevet/internal/checker"
    "github.com/ComplianceVet/compliancevet/internal/cluster"
    "github.com/ComplianceVet/compliancevet/internal/rules"
    "github.com/ComplianceVet/compliancevet/internal/scorer"

    _ "github.com/ComplianceVet/compliancevet/internal/rules/section1"
    _ "github.com/ComplianceVet/compliancevet/internal/rules/section4"
)

func RunLiveClusterCISScan(kubeContext, namespace string) (*CISResult, error) {
    client, err := cluster.New(cluster.Options{
        KubeContext:   kubeContext,
        Namespace:     namespace,
        AllNamespaces: namespace == "",
    })
    if err != nil {
        return nil, err
    }

    ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
    defer cancel()

    objects, err := client.FetchObjects(ctx)
    if err != nil {
        return nil, err
    }

    results := checker.Run(objects, checker.Config{
        Sections: []rules.CISSection{
            rules.SectionControlPlane,
            rules.SectionPolicies,
        },
        MinSeverity: rules.SeverityMedium,
    })

    return &CISResult{
        Score:   scorer.Compute(results),
        Results: results,
    }, nil
}
```

### 3. `k8svet report` — K8sVet 統合レポートへの埋め込み

ComplianceVet の `CheckResult` を K8sVet の統合レポートに組み込む際のデータ構造マッピング:

```go
package k8svet

import (
    cvRules "github.com/ComplianceVet/compliancevet/internal/rules"
)

// K8sVetFinding は K8sVet 共通の違反表現。
type K8sVetFinding struct {
    ToolName    string   // "ComplianceVet"
    RuleID      string   // "CV1001"
    Standard    string   // "CIS 1.2.1"
    Severity    string   // "CRITICAL"
    Status      string   // "FAIL"
    Resource    string   // "Pod/kube-system/kube-apiserver"
    Message     string
    Remediation string
    FilePath    string
}

// FromCheckResult は ComplianceVet の結果を K8sVet 共通形式に変換する。
func FromCheckResult(r cvRules.CheckResult) K8sVetFinding {
    return K8sVetFinding{
        ToolName:    "ComplianceVet",
        RuleID:      r.RuleID,
        Standard:    r.CISRef,
        Severity:    string(r.Severity),
        Status:      string(r.Status),
        Resource:    r.Resource,
        Message:     r.Message,
        Remediation: r.Remediation,
        FilePath:    r.FilePath,
    }
}

// FilterFails は FAIL ステータスの結果のみ返す（k8svet scan の出力向け）。
func FilterFails(results []cvRules.CheckResult) []cvRules.CheckResult {
    var out []cvRules.CheckResult
    for _, r := range results {
        if r.Status == cvRules.StatusFail {
            out = append(out, r)
        }
    }
    return out
}
```

## --compliance フラグのマッピング

k8svet の `--compliance` フラグと ComplianceVet のセクションの対応:

```go
var complianceSections = map[string][]rules.CISSection{
    "cis": {
        rules.SectionControlPlane,
        rules.SectionEtcd,
        rules.SectionWorkerNodes,
        rules.SectionPolicies,
    },
    "nsa":     {rules.SectionNSACISA},
    "nsa-cisa": {rules.SectionNSACISA},
    "pci-dss": {rules.SectionPCIDSS},
    "pci":     {rules.SectionPCIDSS},
    "all": {
        rules.SectionControlPlane,
        rules.SectionEtcd,
        rules.SectionWorkerNodes,
        rules.SectionPolicies,
        rules.SectionNSACISA,
        rules.SectionPCIDSS,
    },
}
```

## ManifestVet / RBACVet 違反の CIS コントロールへのマッピング

ComplianceVet v0.6.0 以降で実装予定。ManifestVet・RBACVet の違反を CIS/NSA コントロールに自動マッピングすることで、重複スキャンなしにコンプライアンス評価を実現する。

```go
// 将来実装予定のインターフェース
type ViolationMapper interface {
    // ManifestVet/RBACVet の違反から対応する ComplianceVet ルールIDを返す
    MapToRuleIDs(toolName string, ruleID string) []string
}

// マッピング例（ドラフト）:
// RBACVet RB1003 (wildcard verb) → CV4001 (CIS 5.1.3)
// RBACVet RB1001 (cluster-admin) → CV5009 (NSA §8.1), CV6003 (PCI Req 7)
// ManifestVet MV2001 (privileged) → CV4006 (CIS 5.2.1), CV6008 (PCI Req 2)
```

## スコアの表示形式

k8svet のスキャン出力に追加するコンプライアンス行の推奨フォーマット:

```
# 簡潔版（scan サブコマンド用）
[ComplianceVet]  CIS v1.9     Score: 72/100  (47 PASS, 12 FAIL, 8 WARN)
[ComplianceVet]  NSA/CISA     Score: 65/100  (21 PASS, 9 FAIL, 3 WARN)
[ComplianceVet]  PCI-DSS v4.0 Score: 88/100  (15 PASS, 2 FAIL, 1 WARN)

# セクション展開版（--verbose フラグ時）
[ComplianceVet]  CIS v1.9  Overall: 72/100
  Control Plane:  85/100   etcd: 100/100   Worker Nodes: 60/100   Policies: 45/100
  ⚠ Critical failures: 2   High failures: 8
```

## セマンティックバージョニングと K8sVet の対応表

| ComplianceVet | K8sVet | 追加機能 |
|---|---|---|
| v0.1.0 | v0.5.0 | CIS スコア表示 |
| v0.3.0 | v0.5.0 | `--compliance pci-dss` フィルタリング |
| v0.5.0 | v0.6.0 | 統合 HTML 監査レポート |
| v0.6.0 | v0.7.0 | カスタムポリシー + 違反マッピング |
