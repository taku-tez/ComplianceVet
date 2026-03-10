# ComplianceVet Roadmap

Kubernetes環境のコンプライアンス自動検証ツール。
CIS Kubernetes Benchmark・NSA/CISA・PCI-DSSなどの業界標準に対するクラスターの準拠状況を自動評価し、監査レポートを生成する。

---

## v0.1.0 — CIS Kubernetes Benchmark (Week 1–3)

**Goal:** CIS Kubernetes Benchmark v1.9 の主要コントロールを自動評価する。

### セクション1: Control Plane
- [ ] 1.1 API Server フラグ検証 (`--anonymous-auth=false`, `--audit-log-path` 等)
- [ ] 1.2 Admission Plugins の有効化確認 (`NodeRestriction`, `PodSecurity` 等)
- [ ] 1.3 Controller Manager フラグ (`--use-service-account-credentials=true` 等)
- [ ] 1.4 Scheduler フラグ (`--profiling=false` 等)

### セクション2: etcd
- [ ] 2.1 etcd の TLS 設定確認
- [ ] 2.2 etcd のデータ暗号化確認

### セクション3: Control Plane 設定
- [ ] 3.1 認証設定 (client certificate / OIDC / webhook)
- [ ] 3.2 監査ログポリシーの適切性確認

### セクション4: ワーカーノード
- [ ] 4.1 kubelet 設定ファイルのパーミッション
- [ ] 4.2 kubelet 認証・認可設定
- [ ] 4.2.1 `--anonymous-auth=false`
- [ ] 4.2.2 `--authorization-mode` が `AlwaysAllow` でないこと
- [ ] 4.2.6 `--protect-kernel-defaults=true`
- [ ] 4.2.10 `--rotate-certificates=true`

### セクション5: Kubernetes Policies
- [ ] 5.1 RBAC と Service Account
- [ ] 5.2 Pod Security Standards (PSS) 準拠確認
- [ ] 5.3 NetworkPolicy の適用確認
- [ ] 5.4 Secret 管理
- [ ] 5.5 Extensible Admission Control
- [ ] 5.7 一般的なポリシー

### スコアリング
- [ ] セクション別スコア (0–100)
- [ ] 全体コンプライアンススコア
- [ ] PASS / FAIL / WARN / NOT_APPLICABLE ステータス
- [ ] 修正優先度付け (Critical / High / Medium / Low)

---

## v0.2.0 — NSA/CISA Kubernetes Hardening Guide (Week 4–5)

**Goal:** NSA/CISA の Kubernetes Hardening Guide (2022) への準拠を評価する。

### Pod セキュリティ
- [ ] 非rootユーザーでの実行強制
- [ ] 不変なファイルシステムの使用
- [ ] 特権コンテナの禁止
- [ ] 不要なLinux Capabilityの削除
- [ ] seccomp / AppArmor プロファイルの適用

### ネットワーク分離
- [ ] namespace 間のデフォルト拒否 NetworkPolicy
- [ ] ロードバランサーの送信元IP制限
- [ ] Ingress TLS 設定確認

### 認証・認可
- [ ] 最小権限の原則 (RBAC)
- [ ] 定期的な証明書ローテーション
- [ ] ServiceAccount トークンの自動マウント制御

### 監査とログ
- [ ] 監査ログの有効化と保持期間
- [ ] 特権操作のログ記録
- [ ] 異常検知設定の確認

---

## v0.3.0 — PCI-DSS (Week 6–7)

**Goal:** PCI-DSS v4.0 のKubernetes環境向けコントロールを評価する。

- [ ] 要件2: セキュアな設定 (デフォルト認証情報の排除)
- [ ] 要件6: システムとソフトウェアの保護 (イメージの脆弱性管理)
- [ ] 要件7: アクセスの制限 (RBAC最小権限)
- [ ] 要件8: ユーザー認証 (強力な認証の強制)
- [ ] 要件10: 監査ログ (監査ログの完全性・保持)
- [ ] 要件11: システムとネットワークの定期テスト
- [ ] カード会員データ環境 (CDE) の namespace 分離確認

---

## v0.4.0 — ライブクラスター評価 (Week 8–9)

**Goal:** 稼働中クラスターに対してリアルタイムにコンプライアンス評価を実行する。

- [ ] `compliancevet --cluster --benchmark cis` でライブ評価
- [ ] `--context` / `--namespace` / `--all-namespaces` サポート
- [ ] GKE / EKS / AKS のマネージドクラスター固有チェックへの対応
  - GKE: Workload Identity, Binary Authorization, Shielded Nodes
  - EKS: IAM Roles for Service Accounts (IRSA), GuardDuty 設定
  - AKS: Microsoft Defender for Containers, Azure Policy
- [ ] ベースライン (前回スキャン結果) との差分表示
- [ ] 違反の経時変化トレンド

---

## v0.5.0 — 監査レポート生成 (Week 10–11)

**Goal:** 監査提出用の正式レポートを自動生成する。

- [ ] HTML シングルファイルレポート (印刷対応)
- [ ] PDF エクスポート
- [ ] Markdown レポート (GitHub Pages 対応)
- [ ] 証拠収集: 違反箇所のYAMLスニペットを自動添付
- [ ] エグゼクティブサマリー (非技術向け概要)
- [ ] コントロール別準拠率グラフ
- [ ] 前回スキャンとの比較セクション
- [ ] 是正措置の追跡 (JIRA/Linear 連携オプション)

---

## v0.6.0 — カスタムポリシー (Week 12)

**Goal:** 組織固有のコンプライアンス要件をカスタム定義できるようにする。

- [ ] YAML ベースのカスタムコントロール定義
- [ ] 既存ルール (CIS/NSA 等) の重み付け変更
- [ ] 特定リソース・namespace の除外設定
- [ ] 組織ポリシーファイル (`.compliancevet.yaml`)
- [ ] ポリシーの継承 (base + override)

---

## K8sVet 取り込み計画

| バージョン | K8sVet対応 | 内容 |
|---|---|---|
| ComplianceVet v0.1.0 完了後 | K8sVet v0.5.0 | `k8svet scan --cluster` に CIS スコア表示を追加 |
| ComplianceVet v0.3.0 完了後 | K8sVet v0.5.0 | `--compliance pci` オプションでフィルタリング |
| ComplianceVet v0.5.0 完了後 | K8sVet v0.6.0 | `k8svet report` コマンドで統合監査レポート生成 |

```bash
# K8sVet統合後のイメージ
k8svet scan --cluster --compliance cis
# → [ComplianceVet]  CIS v1.9  Score: 72/100  (47 PASS, 12 FAIL, 8 WARN)

k8svet report --cluster --output report.html
# → 全ツールの結果 + コンプライアンス評価を単一HTMLに統合
```

### 統合レポートへの貢献
ComplianceVet は K8sVet の `k8svet report` コマンドにおいて中核を担う。
ManifestVet/RBACVet 等の違反を CIS/NSA コントロールに自動マッピングし、
既存スキャン結果を再利用してコンプライアンス評価を生成する。

---

## ルールID体系

```
CV1xxx  CIS Kubernetes Benchmark (Control Plane)
CV2xxx  CIS Kubernetes Benchmark (etcd)
CV3xxx  CIS Kubernetes Benchmark (Worker Node)
CV4xxx  CIS Kubernetes Benchmark (Policies)
CV5xxx  NSA/CISA Hardening Guide
CV6xxx  PCI-DSS
CV7xxx  カスタムポリシー
```
