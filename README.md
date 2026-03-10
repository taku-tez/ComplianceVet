# ComplianceVet

Kubernetes 環境のコンプライアンス自動検証エンジン。
CIS Kubernetes Benchmark v1.9・NSA/CISA Kubernetes Hardening Guide・PCI-DSS v4.0 に対するクラスターの準拠状況を自動評価し、監査レポートを生成する。

> **このツールは [K8sVet](https://github.com/k8svet) エコシステムの一部として設計されています。**
> 単体でも動作しますが、`k8svet scan --compliance cis` のように K8sVet 経由で呼び出されることを主な利用シーンとして想定しています。

---

## K8sVet との関係

ComplianceVet は K8sVet ツール群の **コンプライアンス評価レイヤー** を担います。

```
┌─────────────────────────────────────────────────────┐
│                      K8sVet CLI                     │
│  k8svet scan --compliance cis --cluster             │
└──────────┬──────────────────────────────────────────┘
           │ 呼び出し
    ┌──────▼──────┐   ┌─────────────┐   ┌──────────────┐
    │ManifestVet  │   │  RBACVet    │   │ComplianceVet │ ← ここ
    │(YAML lint)  │   │(RBAC audit) │   │(CIS/NSA/PCI) │
    └─────────────┘   └─────────────┘   └──────────────┘
           │                │                  │
           └────────────────┴──────────────────┘
                            │
                    ┌───────▼───────┐
                    │ Unified Report│
                    │ (HTML / JSON) │
                    └───────────────┘
```

### K8sVet からの呼び出しイメージ

```bash
# CIS スコアをスキャン結果に追加
k8svet scan --cluster --compliance cis
# → [ComplianceVet]  CIS v1.9  Score: 72/100  (47 PASS, 12 FAIL, 8 WARN)

# PCI-DSS フィルタリング
k8svet scan --cluster --compliance pci-dss

# 統合監査レポート (ManifestVet / RBACVet / ComplianceVet の結果を統合)
k8svet report --cluster --output report.html
```

### 統合における ComplianceVet の役割

| K8sVet バージョン | 機能 |
|---|---|
| v0.5.0 | `k8svet scan --cluster` に CIS スコア表示を追加 |
| v0.5.0 | `--compliance pci` オプションでフィルタリング |
| v0.6.0 | `k8svet report` で統合 HTML 監査レポートを生成 |

ManifestVet・RBACVet 等が検出した違反を CIS/NSA コントロールに自動マッピングし、既存スキャン結果を再利用してコンプライアンス評価を生成することで、重複スキャンなしに統合レポートを実現します。

---

## サポート標準

| セクション | 標準 | バージョン | ルール数 |
|---|---|---|---|
| Section 1–4 | CIS Kubernetes Benchmark | v1.9 | 31 |
| Section 5 | NSA/CISA Kubernetes Hardening Guide | 2022 | 13 |
| Section 6 | PCI-DSS | v4.0 | 8 |

**合計: 52 ルール**

---

## インストール

```bash
go install github.com/ComplianceVet/compliancevet/cmd/compliancevet@latest
```

またはソースからビルド:

```bash
git clone https://github.com/ComplianceVet/compliancevet
cd compliancevet
make build          # bin/compliancevet を生成
make install        # $GOPATH/bin にインストール
```

---

## 使い方

### マニフェストファイルのスキャン

```bash
# ディレクトリを再帰的にスキャン（全標準）
compliancevet scan ./k8s/

# 特定の標準のみ
compliancevet scan --benchmark cis ./k8s/
compliancevet scan --benchmark nsa ./k8s/
compliancevet scan --benchmark pci-dss ./k8s/

# テーブル形式で出力
compliancevet scan -o table ./k8s/

# HTML レポートをファイルに保存
compliancevet scan -o html ./k8s/ > report.html

# JSON 出力（CI/CD パイプライン向け）
compliancevet scan -o json ./k8s/ > report.json

# スコアが 80 未満なら CI を失敗させる
compliancevet scan --fail-on-score 80 ./k8s/

# Critical のみ表示
compliancevet scan --min-severity CRITICAL ./k8s/

# 特定ルールを除外
compliancevet scan --ignore CV1003,CV1004 ./k8s/
```

### ライブクラスターのスキャン

```bash
# 現在の kubectl コンテキストでスキャン
compliancevet cluster

# コンテキストを指定
compliancevet cluster --context production-cluster

# 特定の標準のみ
compliancevet cluster --benchmark cis

# 特定 Namespace のみ
compliancevet cluster -n kube-system

# HTML レポートを生成
compliancevet cluster -o html > cluster-report.html
```

### 出力例

```
ComplianceVet — CIS Kubernetes Benchmark v1.9

Scanned: 42 file(s)

Section 1: Control Plane          Score: 85/100
  CV1003   FAIL  MEDIUM    --audit-log-maxage must be >= 30 [Pod/kube-system/kube-apiserver]
           ↳ Remediation: Set --audit-log-maxage=30 or greater in kube-apiserver arguments

Section 4: Policies               Score: 77/100
  CV4001   FAIL  CRITICAL  Role has wildcard verb '*' in rules [ClusterRole/super-admin]
           ↳ Remediation: Replace wildcard verbs with explicit verbs

Section 5: NSA/CISA               Score: 65/100
  CV5007   FAIL  HIGH      Ingress has no TLS configuration [Ingress/staging/app]
           ↳ Remediation: Configure tls section in Ingress spec with a valid TLS secret

Overall Score: 78/100
  PASS: 38  FAIL: 8  WARN: 6  NOT_APPLICABLE: 14

  Critical failures: 1
  High failures:     5
```

---

## ルール一覧

### Section 1: CIS Control Plane (CV1xxx)

| Rule ID | CIS Ref | 説明 | Severity |
|---|---|---|---|
| CV1001 | 1.2.1 | API Server `--anonymous-auth=false` | CRITICAL |
| CV1002 | 1.2.22 | API Server `--audit-log-path` 設定 | HIGH |
| CV1003 | 1.2.23 | `--audit-log-maxage >= 30` | MEDIUM |
| CV1004 | 1.2.24 | `--audit-log-maxbackup >= 10` | MEDIUM |
| CV1005 | 1.2.25 | `--audit-log-maxsize >= 100` | MEDIUM |
| CV1006 | 1.2.7 | `--authorization-mode` に AlwaysAllow を含まない | CRITICAL |
| CV1007 | 1.2.8 | `--authorization-mode` に Node,RBAC を含む | HIGH |
| CV1008 | 1.2.16 | NodeRestriction Admission Plugin 有効化 | HIGH |
| CV1009 | 1.2.17 | PodSecurity Admission Plugin 有効化 | HIGH |
| CV1010 | 1.2.29 | TLS 証明書・秘密鍵の設定 | CRITICAL |
| CV1011 | 1.3.2 | Controller Manager `--use-service-account-credentials=true` | HIGH |
| CV1012 | 1.3.6 | `RotateKubeletServerCertificate` 無効化禁止 | MEDIUM |
| CV1013 | 1.4.1 | Scheduler `--profiling=false` | LOW |

### Section 2: CIS etcd (CV2xxx)

| Rule ID | CIS Ref | 説明 | Severity |
|---|---|---|---|
| CV2001 | 2.1 | etcd TLS クライアント証明書・鍵の設定 | CRITICAL |
| CV2002 | 2.2 | etcd `--client-cert-auth=true` | CRITICAL |
| CV2003 | 2.3 | etcd `--auto-tls` 無効化 | HIGH |
| CV2004 | 2.4 | etcd ピア間 TLS 設定 | HIGH |
| CV2005 | 2.5 | etcd `--peer-client-cert-auth=true` | HIGH |
| CV2006 | 2.6 | etcd `--peer-auto-tls` 無効化 | HIGH |

### Section 3: CIS Worker Nodes / kubelet (CV3xxx)

| Rule ID | CIS Ref | 説明 | Severity |
|---|---|---|---|
| CV3001 | 4.2.1 | kubelet 匿名認証の無効化 | CRITICAL |
| CV3002 | 4.2.2 | kubelet `authorization.mode` が AlwaysAllow でない | CRITICAL |
| CV3003 | 4.2.6 | kubelet `protectKernelDefaults=true` | HIGH |
| CV3004 | 4.2.10 | kubelet `rotateCertificates=true` | HIGH |
| CV3005 | 4.2.3 | kubelet `clientCAFile` の設定 | HIGH |
| CV3006 | 4.2.4 | kubelet 読み取り専用ポートの無効化 | MEDIUM |

### Section 4: CIS Policies (CV4xxx)

| Rule ID | CIS Ref | 説明 | Severity |
|---|---|---|---|
| CV4001 | 5.1.3 | ClusterRole/Role にワイルドカード verb `*` なし | CRITICAL |
| CV4002 | 5.1.3 | ClusterRole/Role にワイルドカード resource `*` なし | HIGH |
| CV4003 | 5.1.1 | default ServiceAccount への権限バインド禁止 | HIGH |
| CV4004 | 5.1.5 | ServiceAccount トークン自動マウント抑制 | MEDIUM |
| CV4005 | 5.2.6 | コンテナの非 root 実行 | HIGH |
| CV4006 | 5.2.1 | 特権コンテナの禁止 | CRITICAL |
| CV4007 | 5.2.2 | hostPID の禁止 | CRITICAL |
| CV4008 | 5.2.3 | hostIPC の禁止 | HIGH |
| CV4009 | 5.2.4 | hostNetwork の禁止 | HIGH |
| CV4010 | 5.3.2 | 各 Namespace に NetworkPolicy の適用 | HIGH |
| CV4011 | 5.4.1 | Secret を平文環境変数に露出しない | MEDIUM |
| CV4012 | 5.4.2 | Secret をコマンド引数に渡さない | MEDIUM |

### Section 5: NSA/CISA Kubernetes Hardening Guide (CV5xxx)

| Rule ID | 節 | 説明 | Severity |
|---|---|---|---|
| CV5001 | §6.2 | `readOnlyRootFilesystem=true` (不変ファイルシステム) | HIGH |
| CV5002 | §6.2 | Linux capabilities を ALL drop | HIGH |
| CV5003 | §6.2 | seccomp プロファイルの設定 | MEDIUM |
| CV5004 | §6.2 | AppArmor プロファイルの設定 | LOW |
| CV5005 | §7.1 | デフォルト拒否 Ingress NetworkPolicy | HIGH |
| CV5006 | §7.1 | デフォルト拒否 Egress NetworkPolicy | MEDIUM |
| CV5007 | §7.2 | Ingress TLS の設定 | HIGH |
| CV5008 | §7.2 | LoadBalancer 送信元 IP 制限 | MEDIUM |
| CV5009 | §8.1 | cluster-admin を非システムアカウントに付与しない | CRITICAL |
| CV5010 | §8.2 | ServiceAccount トークンの自動マウント無効化 | MEDIUM |
| CV5011 | §8.1 | ワイルドカード権限 ClusterRole をユーザーにバインドしない | HIGH |
| CV5012 | §9.1 | 監査ログの有効化 | HIGH |
| CV5013 | §9.1 | 監査ポリシーファイルの設定 | MEDIUM |

### Section 6: PCI-DSS v4.0 (CV6xxx)

| Rule ID | 要件 | 説明 | Severity |
|---|---|---|---|
| CV6001 | Req 2.2 | default ServiceAccount の排除 | HIGH |
| CV6002 | Req 6.3 | コンテナイメージの `latest` タグ禁止 | HIGH |
| CV6003 | Req 7.2 | ワークロード SA への cluster-admin バインド禁止 | CRITICAL |
| CV6004 | Req 8.2 | anonymous 認証の無効化 | CRITICAL |
| CV6005 | Req 10.5 | 監査ログ保持期間 >= 365 日 | HIGH |
| CV6006 | Req 10.2 | 監査ログの有効化 | CRITICAL |
| CV6007 | Req 11.4 | CDE Namespace のネットワーク分離 | CRITICAL |
| CV6008 | Req 2.2 | 特権コンテナの禁止 | CRITICAL |

---

## Go ライブラリとして利用する（K8sVet 統合）

ComplianceVet は CLI としてだけでなく、**Go パッケージとして K8sVet に直接組み込む**ことができます。

### インストール

```bash
go get github.com/ComplianceVet/compliancevet
```

### 基本的な使い方

```go
import (
    "github.com/ComplianceVet/compliancevet/internal/checker"
    "github.com/ComplianceVet/compliancevet/internal/parser"
    "github.com/ComplianceVet/compliancevet/internal/report"
    "github.com/ComplianceVet/compliancevet/internal/rules"
    "github.com/ComplianceVet/compliancevet/internal/scanner"

    // 使用するセクションを blank import で登録
    _ "github.com/ComplianceVet/compliancevet/internal/rules/section1"
    _ "github.com/ComplianceVet/compliancevet/internal/rules/section4"
    _ "github.com/ComplianceVet/compliancevet/internal/rules/section5"
)

func RunComplianceCheck(paths []string) (report.Report, error) {
    // 1. ファイルをスキャン
    objects, _, err := scanner.Scan(scanner.ScanOptions{
        Paths:     paths,
        Recursive: true,
    })
    if err != nil {
        return report.Report{}, err
    }

    // 2. チェック実行
    results := checker.Run(objects, checker.Config{
        // CIS のみ評価する場合
        Sections: []rules.CISSection{
            rules.SectionControlPlane,
            rules.SectionEtcd,
            rules.SectionWorkerNodes,
            rules.SectionPolicies,
        },
        MinSeverity: rules.SeverityHigh, // HIGH 以上のみ
    })

    // 3. レポート生成
    return report.New(results, paths), nil
}
```

### ライブクラスターからオブジェクトを取得して評価

```go
import (
    "context"
    "github.com/ComplianceVet/compliancevet/internal/cluster"
    "github.com/ComplianceVet/compliancevet/internal/checker"
    "github.com/ComplianceVet/compliancevet/internal/report"
    "github.com/ComplianceVet/compliancevet/internal/rules"

    _ "github.com/ComplianceVet/compliancevet/internal/rules/section1"
    _ "github.com/ComplianceVet/compliancevet/internal/rules/section4"
)

func RunLiveClusterCheck(kubeContext string) (report.Report, error) {
    client, err := cluster.New(cluster.Options{
        KubeContext:   kubeContext,
        AllNamespaces: true,
    })
    if err != nil {
        return report.Report{}, err
    }

    objects, err := client.FetchObjects(context.Background())
    if err != nil {
        return report.Report{}, err
    }

    results := checker.Run(objects, checker.Config{})
    return report.New(results, []string{"<live cluster>"}), nil
}
```

### CheckResult の構造

```go
type CheckResult struct {
    RuleID      string      // "CV1001"
    CISRef      string      // "CIS 1.2.1" or "NSA/CISA §6.2"
    Section     CISSection  // "1", "2", ..., "6"
    Status      Status      // PASS / FAIL / WARN / NOT_APPLICABLE
    Severity    Severity    // CRITICAL / HIGH / MEDIUM / LOW
    Description string      // ルールの説明
    Message     string      // 違反の詳細メッセージ
    Resource    string      // "Deployment/default/web-app"
    FilePath    string      // ソースファイルパス or "<cluster>"
    Remediation string      // 修正方法
}
```

### K8sVet でのスコア表示例

```go
rep, err := RunComplianceCheck(manifestPaths)
if err != nil {
    log.Fatal(err)
}

score := rep.Score
fmt.Printf("[ComplianceVet]  CIS v1.9  Score: %.0f/100  (%d PASS, %d FAIL, %d WARN)\n",
    score.Score,
    totalPass(score),
    totalFail(score),
    totalWarn(score),
)
```

---

## CI/CD 連携

### GitHub Actions

```yaml
- name: Compliance Check
  run: |
    compliancevet scan \
      --benchmark cis \
      --min-severity HIGH \
      --fail-on-score 70 \
      -o json ./k8s/ > compliance-report.json

- name: Upload Report
  uses: actions/upload-artifact@v4
  with:
    name: compliance-report
    path: compliance-report.json
  if: always()
```

### 終了コード

| コード | 意味 |
|---|---|
| `0` | 全チェック PASS（または `--fail-on-score` 基準を満たす） |
| `1` | FAIL が存在する（または `--fail-on-score` 基準を下回る） |
| `2` | 致命的エラー（パース失敗、ファイルなし等） |

---

## プロジェクト構造

```
compliancevet/
├── cmd/compliancevet/     # バイナリエントリポイント
├── cli/                   # cobra コマンド (scan, cluster, version)
├── internal/
│   ├── parser/            # YAML/JSON → K8sObject パーサー
│   ├── scanner/           # ファイルシステム走査
│   ├── cluster/           # ライブクラスタークライアント (client-go)
│   ├── rules/             # ルール定義
│   │   ├── section1/      # CV1xxx: CIS Control Plane
│   │   ├── section2/      # CV2xxx: CIS etcd
│   │   ├── section3/      # CV3xxx: CIS Worker Nodes
│   │   ├── section4/      # CV4xxx: CIS Policies
│   │   ├── section5/      # CV5xxx: NSA/CISA
│   │   └── section6/      # CV6xxx: PCI-DSS
│   ├── checker/           # ルールエンジン
│   ├── scorer/            # スコア計算
│   └── report/            # 出力フォーマット (text/table/json/html)
└── ROADMAP.md
```

---

## ライセンス

MIT
