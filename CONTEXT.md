# CONTEXT.md

このファイルはプロジェクトの設計とその経緯を記録したものです。
Claude Code に読み込ませることでコンテキストを共有するために使います。

## プロジェクト概要

Junos ルータから，routing-instance ごとの経路情報を収集する **junos-collector** を Go で実装する。
数百の routing-instance があっても，すべてのインスタンスの経路表（FIB・BGP 経路）を外部から取得したい。
将来的には junos 以外にも対応させたいので，Junos 用の collector という意味で名称に `junos` を付けた。

## 取得したい情報

- **FIB**（転送テーブル，`ip route show` 相当，Junos では `show route table <instance>.inet.0` 相当）
- **BGP RIB**（adj-rib-in および loc-rib，BGP が受信した経路と best path）
- routing-instance すべてのものを取得できること

## アーキテクチャ（junos-collector の場合）

```
[Junos router]
    │  JTI / gNMI (gRPC, OpenConfig) でストリーム送信
    │  センサーパス:
    │    /network-instances/network-instance/afts/          (FIB)
    │    /network-instances/network-instance/protocols/protocol/bgp/  (BGP RIB)
    ▼
[collector (Go)]
    └─ gRPC ストリーム受信
    └─ routing-instance ごとにパース
    └─ まず stdout 出力（第一目標）
```

## 設計上の主な決定とその経緯

### NETCONF ではなく JTI を採用した理由

routing-instance が多数になることが考えられるので，collector から router へ大量のリクエストを投げるのは router 側の負荷・接続数の観点から現実的でないと判断した。
JTI（push 型）であれば，router 側が変化を送信するので collector は gRPC ストリームを数本張って待ち受けるだけで済む。

### 認証情報を平文で流さない

初期実装は `insecure.NewCredentials()` で TLS なし，かつ username/password を
`metadata.AppendToOutgoingContext` で直接載せていたため，認証情報がネットワーク上を
平文で流れていた。さらに `-password` フラグはコマンドライン引数なので `ps` から
他ユーザに見えてしまう。

対処として:

- TLS を既定（`-tls`，既定 true）にし，`credentials.NewTLS` を使う
- 認証情報は `grpc.WithPerRPCCredentials` で渡す。`RequireTransportSecurity()` が
  true なので，平文接続では gRPC 自身が送信を拒否する。metadata に直接載せる方式と
  違い，設定ミスで平文送信になることがない
- パスワードは `GNMI_PASSWORD` 環境変数 → `-password-file` → `-password` の順に解決し，
  フラグが使われた場合は警告する

ラボで Junos を `clear-text` のまま使う場合は `-tls=false` で従来動作に戻せるが，
警告を出す。

### ポーリング vs ストリーミング

20 秒オーダーの同期が必要だが，routing-instance が多くなるとポーリングが破綻するためストリーミング（JTI, push 型）を採用。

## 環境

| 項目 | 内容 |
|---|---|
| Router | Junos 23.4R2-S2.1（ラボ用: vJunos-router-23.4R2-S2.1） |
| Collector 言語 | Go |
| 手元端末 | MacBook Air (macOS) |
| routing-instance 数 | 最大数百個 |

## ラボ環境（Proxmox VE 9.1）

HV: Proxmox VE 9.1, CPU: AMD Ryzen 9 3950X

### vJunos VM 設定（動作確認済みの設定）

| 項目 | 設定値 |
|---|---|
| Machine | q35 |
| CPU | max（`host` でも起動するが後述の問題あり） |
| Memory | 4096 MB |
| NIC | VirtIO (virtio-net-pci) |
| NUMA | 有効（hugepages 使用に必要） |
| Hugepages | 2MB（Proxmox ホストで `echo 256 > /proc/sys/vm/nr_hugepages` が必要） |
| Disk | qcow2 を `qm importdisk` で ZFS にインポート後アタッチ |

### 判明した問題と対処

**hugepages が必要**
vJunos 内部の FPC（PFE）は DPDK（riot プロセス）を使うため，Proxmox ホストで hugepages を確保し，VM にも有効化する必要がある。設定しないと `cannot map 65536 frames for edmem` で PANIC する。

```bash
# Proxmox ホストで実行
echo 256 > /proc/sys/vm/nr_hugepages
qm set <vmid> -numa 1
qm set <vmid> -hugepages 2
```

**AMD CPU で riot (DPDK) が Segfault する**
hugepages を設定しても riot が Segmentation fault で落ちる。原因は AMD + Nested KVM 環境での DPDK の TSC（タイマー）検出問題と考えられる（`constant_tsc=no nonstop_tsc=no` 警告が出る）。

- Proxmox 9 では `-cpu host,+invtsc` のようなフラグ追加が制限されており回避が難しい
- `cpu: max` に変えても同様に Segfault する
- **次の対処**: `vJunos-router-25.4R1.12` で試す（新しい DPDK で改善している可能性）

**RE（コントロールプレーン）は起動する**
riot が落ちても FreeBSD ベースの RE は正常起動し，Junos CLI にログインできる（`root` / パスワードなし）。ただし FPC が上がらないため `ge-0/0/x` などのデータプレーンインターフェースは見えない。

**FPC Linux へのアクセス**
RE シェルから `ssh 128.0.0.16` で FPC Linux（内部 IP）に入れる。

## 今後の確認事項

- `vJunos-router-25.4R1.12` で riot クラッシュが解消するか確認する
- 解消したら管理 IP（fxp0）を設定して SSH・gNMI アクセスを確認する
- JTI / gNMI のセンサーパスで FIB・BGP RIB が実際に取得できるか確認する
- adj-rib-in の取得可否（ネイバーが複数の場合の扱いも含む）
