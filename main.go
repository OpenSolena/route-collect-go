package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// passwordEnv はパスワードの推奨受け渡し方法。コマンドライン引数は ps で
// 他ユーザから見えてしまうため，環境変数かファイルを優先する。
const passwordEnv = "GNMI_PASSWORD"

var (
	target   = flag.String("target", "localhost:32767", "gNMI ターゲット (host:port)")
	username = flag.String("username", "", "認証ユーザー名")
	password = flag.String("password", "", "認証パスワード（非推奨: ps で露出する。"+passwordEnv+" かファイルを使うこと）")

	passwordFile = flag.String("password-file", "", "認証パスワードを読み込むファイル")

	// TLS 関連。既定で TLS を要求し，パスワードが平文で流れないようにする。
	useTLS     = flag.Bool("tls", true, "TLS を使用する（false にすると認証情報が平文で流れる）")
	caFile     = flag.String("ca", "", "サーバ証明書を検証する CA 証明書 (PEM)。省略時はシステムの信頼ストア")
	certFile   = flag.String("cert", "", "クライアント証明書 (PEM)。mutual TLS 用")
	keyFile    = flag.String("key", "", "クライアント秘密鍵 (PEM)。mutual TLS 用")
	serverName = flag.String("server-name", "", "証明書検証に使うサーバ名（省略時は -target のホスト名）")
	skipVerify = flag.Bool("tls-skip-verify", false, "サーバ証明書を検証しない（ラボ専用・中間者攻撃に対して無防備）")

	// updatesOnly は初期同期（現在の全状態のダンプ）を抑止する。
	// フルルートを持つルータでは初期同期が巨大になるため既定で有効。
	updatesOnly = flag.Bool("updates-only", true, "初期同期を省略し，以降の更新のみ受信する")
	mode        = flag.String("mode", "onchange", "サブスクリプションモード: onchange | sample")
	// gNMI の既定は JSON だが，Junos の AFT センサーは JSON を扱えず
	// 「json encoding not supported for sensor」を返す。既定を proto にする。
	encoding = flag.String("encoding", "proto", "エンコーディング: proto | json | json_ietf | ascii | bytes")

	// AFT パス (/network-instances/network-instance/afts) は Junos 26.2R1.7 の
	// vJunos で "Unsupported subscription path" となるため既定から外した。
	pathList = flag.String("paths",
		"/network-instances/network-instance/protocols/protocol/bgp/rib",
		"購読するパス（カンマ区切り）")
	// sample モードは毎インターバルで全状態を送るため，updates-only は初回しか効かない。
	sampleInterval = flag.Duration("sample-interval", 20*time.Second, "sample モード時の送信間隔")
	heartbeat      = flag.Duration("heartbeat", 0, "onchange モード時のハートビート間隔（0 で無効）")
)

// Junos の gNMI デフォルトポートは 32767

// userPassCreds は username/password を gRPC の per-RPC 認証情報として運ぶ。
// RequireTransportSecurity が true なので，TLS でない接続に対して gRPC 自身が
// 送信を拒否する。metadata に直接載せる方式と違い，平文送信を取り違えようがない。
type userPassCreds struct {
	username string
	password string
}

func (c userPassCreds) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{
		"username": c.username,
		"password": c.password,
	}, nil
}

func (c userPassCreds) RequireTransportSecurity() bool { return true }

// resolvePassword はパスワードを環境変数・ファイル・フラグの順に解決する。
// フラグは ps から見えるため，使われた場合は警告する。
func resolvePassword() (string, error) {
	if v := os.Getenv(passwordEnv); v != "" {
		return v, nil
	}
	if *passwordFile != "" {
		b, err := os.ReadFile(*passwordFile)
		if err != nil {
			return "", fmt.Errorf("パスワードファイル読み込み失敗: %w", err)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	if *password != "" {
		log.Printf("警告: -password は ps で他ユーザから見えます。%s 環境変数か -password-file を使ってください", passwordEnv)
		return *password, nil
	}
	return "", nil
}

// buildTLSConfig は各フラグから TLS 設定を組み立てる。
func buildTLSConfig() (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: *skipVerify,
	}

	switch {
	case *serverName != "":
		cfg.ServerName = *serverName
	default:
		host, _, err := net.SplitHostPort(*target)
		if err != nil {
			return nil, fmt.Errorf("-target のホスト名を取得できません: %w", err)
		}
		cfg.ServerName = host
	}

	if *caFile != "" {
		pem, err := os.ReadFile(*caFile)
		if err != nil {
			return nil, fmt.Errorf("CA 証明書読み込み失敗: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA 証明書 %s に有効な PEM が含まれていません", *caFile)
		}
		cfg.RootCAs = pool
	}

	// mutual TLS。Junos 側で mutual-authentication を設定した場合に使う。
	if (*certFile == "") != (*keyFile == "") {
		return nil, fmt.Errorf("-cert と -key は両方指定してください")
	}
	if *certFile != "" {
		pair, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			return nil, fmt.Errorf("クライアント証明書読み込み失敗: %w", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}

	return cfg, nil
}

func main() {
	flag.Parse()

	pass, err := resolvePassword()
	if err != nil {
		log.Fatalf("%v", err)
	}

	opts := []grpc.DialOption{}
	ctx := context.Background()

	if *useTLS {
		tlsCfg, err := buildTLSConfig()
		if err != nil {
			log.Fatalf("TLS 設定に失敗: %v", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))

		// TLS 上でのみ per-RPC 認証情報を渡す。平文接続なら gRPC 側が送信を拒否する。
		if *username != "" {
			opts = append(opts, grpc.WithPerRPCCredentials(userPassCreds{
				username: *username,
				password: pass,
			}))
		}
		if *skipVerify {
			log.Printf("警告: -tls-skip-verify によりサーバ証明書を検証しません。ラボ以外では使わないでください")
		}
	} else {
		// 平文フォールバック。認証情報がネットワーク上を平文で流れる。
		log.Printf("警告: -tls=false です。認証情報が平文で流れます。ラボ以外では使わないでください")
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if *username != "" {
			ctx = metadata.AppendToOutgoingContext(ctx, "username", *username, "password", pass)
		}
	}

	conn, err := grpc.NewClient(*target, opts...)
	if err != nil {
		log.Fatalf("接続失敗: %v", err)
	}
	defer conn.Close()

	client := gnmipb.NewGNMIClient(conn)

	stream, err := client.Subscribe(ctx)
	if err != nil {
		log.Fatalf("Subscribe 失敗: %v", err)
	}

	subMode, err := subscriptionMode(*mode)
	if err != nil {
		log.Fatalf("%v", err)
	}

	enc, err := encodingValue(*encoding)
	if err != nil {
		log.Fatalf("%v", err)
	}

	// パスをひとつでも Junos が拒否するとストリーム全体が落ちるため，
	// 切り分け時は -paths で 1 本だけ購読できるようにしておく。
	var paths []string
	for _, p := range strings.Split(*pathList, ",") {
		if p = strings.TrimSpace(p); p != "" {
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 {
		log.Fatalf("-paths が空です")
	}

	var subs []*gnmipb.Subscription
	for _, p := range paths {
		s := &gnmipb.Subscription{
			Path: ocPath(p),
			Mode: subMode,
		}
		switch subMode {
		case gnmipb.SubscriptionMode_SAMPLE:
			s.SampleInterval = uint64(*sampleInterval)
		case gnmipb.SubscriptionMode_ON_CHANGE:
			s.HeartbeatInterval = uint64(*heartbeat)
		}
		subs = append(subs, s)
	}

	req := &gnmipb.SubscribeRequest{
		Request: &gnmipb.SubscribeRequest_Subscribe{
			Subscribe: &gnmipb.SubscriptionList{
				Mode:         gnmipb.SubscriptionList_STREAM,
				Encoding:     enc,
				UpdatesOnly:  *updatesOnly,
				Subscription: subs,
			},
		},
	}

	if err := stream.Send(req); err != nil {
		log.Fatalf("SubscribeRequest 送信失敗: %v", err)
	}

	if *updatesOnly {
		log.Printf("Subscribe 開始（mode=%s, encoding=%s, 初期同期なし）。sync_response を待機中...", *mode, *encoding)
	} else {
		log.Printf("Subscribe 開始（mode=%s, encoding=%s, 初期同期あり）。更新を待機中...", *mode, *encoding)
	}

	synced := false
	for {
		resp, err := stream.Recv()
		if err != nil {
			log.Fatalf("ストリームエラー: %v", err)
		}

		// updates-only 有効時はここまで何も届かず，最初に sync_response が来る。
		// 以降が「初期状態ではない実際の変化」になる。
		if resp.GetSyncResponse() {
			synced = true
			log.Printf("sync_response 受信。ここから先が更新分です")
			continue
		}
		if !synced {
			log.Printf("[初期同期] %v", resp)
			continue
		}
		fmt.Printf("%v\n", resp)
	}
}

// encodingValue はフラグ文字列を gNMI のエンコーディングに変換する。
func encodingValue(s string) (gnmipb.Encoding, error) {
	switch s {
	case "proto":
		return gnmipb.Encoding_PROTO, nil
	case "json":
		return gnmipb.Encoding_JSON, nil
	case "json_ietf":
		return gnmipb.Encoding_JSON_IETF, nil
	case "ascii":
		return gnmipb.Encoding_ASCII, nil
	case "bytes":
		return gnmipb.Encoding_BYTES, nil
	default:
		return 0, fmt.Errorf("未知のエンコーディング %q (proto | json | json_ietf | ascii | bytes)", s)
	}
}

// subscriptionMode はフラグ文字列を gNMI のサブスクリプションモードに変換する。
func subscriptionMode(s string) (gnmipb.SubscriptionMode, error) {
	switch s {
	case "onchange":
		return gnmipb.SubscriptionMode_ON_CHANGE, nil
	case "sample":
		return gnmipb.SubscriptionMode_SAMPLE, nil
	default:
		return 0, fmt.Errorf("未知のモード %q (onchange | sample)", s)
	}
}

// ocPath はスラッシュ区切りの OpenConfig パス文字列を gnmi.Path に変換する。
func ocPath(s string) *gnmipb.Path {
	var elems []*gnmipb.PathElem
	for _, seg := range strings.Split(strings.TrimPrefix(s, "/"), "/") {
		if seg != "" {
			elems = append(elems, &gnmipb.PathElem{Name: seg})
		}
	}
	return &gnmipb.Path{Elem: elems}
}
