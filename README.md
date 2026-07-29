# route-collect-go

Junos ルータから **gNMI / JTI（Juniper Telemetry Interface）**で経路情報を購読し，
受信した内容を標準出力に流す collector です。

routing-instance が数百規模になると，collector からルータへ問い合わせを繰り返す
ポーリング型（NETCONF など）は接続数・ルータ側負荷の面で現実的ではありません。
本ツールは push 型のストリーミングテレメトリを使い，gRPC ストリームを張って
待ち受けるだけで全 routing-instance の変化を受け取れるようにしています。

現時点では受信した gNMI の `SubscribeResponse` をそのまま出力します。
routing-instance ごとのパースや FIB の取り込みは今後の課題です。

## できること

- OpenConfig パスの gNMI STREAM 購読（`ON_CHANGE` / `SAMPLE`）
- TLS を既定にした接続と，per-RPC での認証情報の受け渡し
- 初期同期（現在の全状態のダンプ）を省略する `updates_only`
- ターゲットの対応モデル一覧の取得（`-capabilities`）
- パスごとの購読可否の実測（`-probe`）

### 現状の制限

- **FIB（AFT）は取得できません。** `/network-instances/network-instance/afts` は
  少なくとも vJunos-router では `Unsupported subscription path` になります。
  実 PFE を持たない環境の制限と思われますが，`-probe` で各自のルータを確認してください。
  そのため既定の購読パスは BGP RIB のみです。
- 出力は `SubscribeResponse` の文字列表現そのままです。構造化出力はまだありません。
- `extension.registered_ext`（JTI のシーケンス番号・タイムスタンプ）はパースしていません。

## インストール

```
go install github.com/OpenSolena/route-collect-go@latest
```

あるいはリポジトリを clone して:

```
go build
```

## 使い方

```
export GNMI_PASSWORD='...'
route-collect-go \
  -target router.example.net:32767 \
  -username telemetry \
  -ca ca.pem
```

`sync_response` を受け取ったあと，更新分が標準出力に流れます。

証明書の SAN に入っている名前と接続先が違う場合（DNS 未登録で IP 接続するときなど）は
`-server-name` で検証名を指定します。

```
route-collect-go \
  -target 192.0.2.1:32767 \
  -server-name router.example.net \
  -username telemetry \
  -ca ca.pem
```

### 対応モデルを見る

```
route-collect-go -target router.example.net:32767 -username telemetry -ca ca.pem -capabilities
```

### 購読できるパスを調べる

```
route-collect-go -target router.example.net:32767 -username telemetry -ca ca.pem -probe
```

**Capabilities のモデル宣言と実際の購読可否は一致しません。** モデルが宣言されていても
テレメトリのセンサーが実装されていないことがあるため（AFT がまさにこれ），
購読可否は `-probe` で実測してください。

`-probe` は候補パスを 1 本ずつ購読し，`sync_response` が返れば `OK`，
`InvalidArgument` が返れば `UNSUPPORTED` と判定します。判定しているのは
**購読が受理されたことだけ**で，そのセンサーが実際にデータを出すかは別途の確認が要ります。

出力例:

```
STATUS       PATH
OK           /interfaces/interface/state/counters
UNSUPPORTED  /network-instances/network-instance/afts
               Unsupported subscription path, ...
OK           /network-instances/network-instance/protocols/protocol/bgp
OK           /network-instances/network-instance/protocols/protocol/bgp/rib
```

## コマンドラインオプション

### 接続

| オプション | 既定値 | 説明 |
|---|---|---|
| `-target` | `localhost:32767` | gNMI ターゲット（`host:port`）。Junos の既定ポートは 32767 |
| `-username` | （なし） | 認証ユーザー名 |
| `-password` | （なし） | 認証パスワード。**非推奨**（`ps` で他ユーザから見える）。使うと警告が出る |
| `-password-file` | （なし） | パスワードを読み込むファイル。末尾の改行は落とす |

パスワードは `GNMI_PASSWORD` 環境変数 → `-password-file` → `-password` の順に解決します。
環境変数かファイルを使ってください。

### TLS

| オプション | 既定値 | 説明 |
|---|---|---|
| `-tls` | `true` | TLS を使う。`false` にすると認証情報が平文で流れる（警告が出る） |
| `-ca` | （なし） | サーバ証明書を検証する CA 証明書（PEM）。省略時はシステムの信頼ストア |
| `-server-name` | `-target` のホスト名 | 証明書検証に使うサーバ名 |
| `-cert` / `-key` | （なし） | クライアント証明書と秘密鍵（PEM）。mutual TLS 用。両方指定する |
| `-tls-skip-verify` | `false` | サーバ証明書を検証しない。**ラボ専用**（中間者攻撃に対して無防備） |

TLS 有効時，認証情報は `grpc.WithPerRPCCredentials` で渡します。
`RequireTransportSecurity()` が true なので，平文接続では gRPC 自身が送信を拒否します。
設定ミスで認証情報が平文で流れることはありません。

自己署名証明書をルータ上で生成した場合，その証明書自体を `-ca` に渡せば検証できます。

### 購読

| オプション | 既定値 | 説明 |
|---|---|---|
| `-paths` | `/network-instances/network-instance/protocols/protocol/bgp/rib` | 購読するパス（カンマ区切り） |
| `-mode` | `onchange` | `onchange` または `sample` |
| `-encoding` | `proto` | `proto` / `json` / `json_ietf` / `ascii` / `bytes` |
| `-updates-only` | `true` | 初期同期を省略し，以降の更新のみ受信する |
| `-sample-interval` | `20s` | `sample` モード時の送信間隔 |
| `-heartbeat` | `0` | `onchange` モード時のハートビート間隔（0 で無効） |

- **`-encoding` の既定を `proto` にしています。** gNMI の既定は JSON ですが，Junos の
  センサーは JSON を受け付けず `json encoding not supported for sensor` を返します。
- **`-updates-only` の既定を `true` にしています。** フルルートを持つルータでは初期同期が
  巨大になるためです。Junos はこのフラグを尊重し，`sync_response` の直後から更新分のみ
  送ってきます。
- `-mode=sample` では毎インターバルで全状態が送られるため，`updates-only` は初回にしか
  効きません。
- **パスをひとつでもルータが拒否するとストリーム全体が落ちます。** 切り分けるときは
  `-paths` に 1 本だけ指定してください。
- パスにキーは不要です。`neighbors/neighbor` を `[neighbor-address=…]` なしで投げても
  サブツリー購読として受理されます。

### 調査

| オプション | 既定値 | 説明 |
|---|---|---|
| `-capabilities` | `false` | Capabilities RPC で対応モデル・エンコーディングを表示して終了 |
| `-probe` | `false` | 候補パスを 1 本ずつ購読して可否を判定し，表示して終了 |
| `-probe-paths` | 後述 | `-probe` で試すパス（カンマ区切り） |
| `-probe-timeout` | `5s` | `-probe` で 1 パスあたり応答を待つ時間 |

`-probe-paths` の既定は BGP・AFT・インターフェースカウンタなど代表的な 9 パスです。

## Junos 側の設定

gRPC の request-response サービスを SSL 付きで有効にします。

```
set system services extension-service request-response grpc ssl port 32767
set system services extension-service request-response grpc ssl local-certificate gnmi-cert
set system services extension-service request-response grpc ssl use-pki
set system services extension-service request-response grpc max-connections 8
```

`use-pki` を付けないと PKI ではなく `security certificates local` 側のストアを見に行くため，
PKI で証明書を作った場合は必須です。

### 証明書をオンボックスで生成する

```
request security pki generate-key-pair certificate-id gnmi-cert type ecdsa size 521
request security pki local-certificate generate-self-signed certificate-id gnmi-cert \
    domain-name router.example.net \
    subject "CN=router.example.net"
```

生成した証明書を取り出して collector 側の `-ca` に渡します。
DNS に登録していないホスト名を SAN に入れた場合は，IP で接続しつつ `-server-name` で
検証名を合わせてください。

### 認証用ユーザ

gNMI のログインには Junos のローカルユーザを使います。

```
set system login user telemetry class read-only
set system login user telemetry authentication plain-text-password
```

### pre-policy の adj-rib-in を見る場合

`adj-rib-in-pre` を購読するには，ネイバーごとに `keep all` が必要です。

```
set protocols bgp group <group> neighbor <neighbor> keep all
```

### 既知の制約: 管理インスタンス（`mgmt_junos`）経由では接続できない

fxp0 を `system management-instance` で `mgmt_junos` に入れていると，gRPC に接続できません。
gRPC デーモンは default instance で動作するため，ワイルドカードで listen していても
`mgmt_junos` に届いた SYN を accept できず，SYN-ACK が返りません
（RST も返らないのでクライアントからはタイムアウトに見えます）。

回避策を 2 つ試しましたが，いずれも不可でした。

- `set system services extension-service request-response grpc routing-instance mgmt_junos`
  — ノブは存在しますが commit が constraint check で失敗します。`system management-instance`
  を設定済みでも「設定されていない」旨のエラーが返ります
- `set system services extension-service request-response grpc ssl address <fxp0 の IP>`
  — バインドに失敗し listener が 1 つも作られなくなります（全アドレスで connection refused）

現状は default instance 側の通常インターフェース（revenue interface）経由で接続する必要があります。

## 動作を確認した環境

| 項目 | 内容 |
|---|---|
| Junos | 26.2R1.7（vJunos-router） |
| Go | 1.26 |
| 証明書 | オンボックス生成の ECDSA P-521 自己署名 |

フルルート（IPv4 約 37 万経路・IPv6 約 25 万経路）を受信している状態で，
`updates_only` により初期同期が 1 件も流れないこと，`sync_response` 直後から
更新分のみ届くことを確認しています。

### 購読を確認できたパス

BGP RIB 配下は以下 12 パスすべてが購読できました。AFT と違い，`afi-safi` 配下を
個別に購読することもできます。

```
/…/bgp/rib
/…/bgp/rib/afi-safis
/…/bgp/rib/afi-safis/afi-safi/{ipv4-unicast,ipv6-unicast}/loc-rib
/…/bgp/rib/afi-safis/afi-safi/{ipv4-unicast,ipv6-unicast}/neighbors/neighbor/adj-rib-in-pre
/…/bgp/rib/afi-safis/afi-safi/{ipv4-unicast,ipv6-unicast}/neighbors/neighbor/adj-rib-in-post
/…/bgp/rib/afi-safis/afi-safi/{ipv4-unicast,ipv6-unicast}/neighbors/neighbor/adj-rib-out-pre
/…/bgp/rib/afi-safis/afi-safi/{ipv4-unicast,ipv6-unicast}/neighbors/neighbor/adj-rib-out-post
```

（`…` は `/network-instances/network-instance/protocols/protocol/bgp` です）

## 今後の予定

- routing-instance ごとのパースと構造化出力
- JTI ヘッダ（`extension.registered_ext`）のパース
- FIB の取得手段の検討（gNMI では取れないため別経路が要る）
- routing-instance が多数ある場合のスループット確認
