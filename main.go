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
	"sort"
	"strings"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
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
	rpcTimeout     = flag.Duration("rpc-timeout", 10*time.Second, "接続と単発 RPC のタイムアウト")

	// 調査用モード。ターゲットが何をサポートしているかを調べて終了する。
	doCapabilities = flag.Bool("capabilities", false, "Capabilities RPC で対応モデル・エンコーディングを表示して終了する")
	doProbe        = flag.Bool("probe", false, "候補パスを 1 本ずつ購読して可否を判定し，結果を表示して終了する")
	probePathList  = flag.String("probe-paths", strings.Join(defaultProbePaths, ","),
		"-probe で試すパス（カンマ区切り）")
	probeTimeout = flag.Duration("probe-timeout", 5*time.Second, "-probe で 1 パスあたり応答を待つ時間")
)

// defaultProbePaths は -probe の既定の候補パス。
// Junos は「モデルは宣言されているがテレメトリのセンサーが無い」ことがあるため，
// Capabilities の結果だけでは購読可否が判断できない。実際に張って確かめる。
var defaultProbePaths = []string{
	"/interfaces/interface/state/counters",
	"/network-instances/network-instance/afts",
	"/network-instances/network-instance/afts/ipv4-unicast",
	"/network-instances/network-instance/afts/ipv6-unicast",
	"/network-instances/network-instance/protocols/protocol/bgp",
	"/network-instances/network-instance/protocols/protocol/bgp/rib",
	"/network-instances/network-instance/protocols/protocol/bgp/neighbors",
	"/network-instances/network-instance/tables",
	"/routing-options",
}

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
	if *rpcTimeout <= 0 {
		log.Fatalf("-rpc-timeout は 0 より大きくしてください")
	}

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

	// grpc.NewClient は接続を待たずに返るため，到達不能なターゲットでは最初の
	// RPC が無期限に待ち続ける。接続時だけは期限付きで待機し，確立後の
	// Subscribe ストリームには期限を設けない。
	dialCtx, cancelDial := context.WithTimeout(ctx, *rpcTimeout)
	defer cancelDial()
	opts = append(opts, grpc.WithBlock())
	conn, err := grpc.DialContext(dialCtx, *target, opts...)
	if err != nil {
		log.Fatalf("接続失敗: %v", err)
	}
	defer conn.Close()

	client := gnmipb.NewGNMIClient(conn)

	// 調査モードは結果を出して終了する。
	if *doCapabilities {
		rpcCtx, cancel := context.WithTimeout(ctx, *rpcTimeout)
		defer cancel()
		if err := runCapabilities(rpcCtx, client); err != nil {
			log.Fatalf("Capabilities 失敗: %v", err)
		}
		return
	}

	subMode, err := subscriptionMode(*mode)
	if err != nil {
		log.Fatalf("%v", err)
	}

	enc, err := encodingValue(*encoding)
	if err != nil {
		log.Fatalf("%v", err)
	}
	if err := validateSubscriptionDurations(); err != nil {
		log.Fatalf("%v", err)
	}
	if *doProbe {
		runProbe(ctx, client, splitPaths(*probePathList), subMode, enc)
		return
	}

	// パスをひとつでも Junos が拒否するとストリーム全体が落ちるため，
	// 切り分け時は -paths で 1 本だけ購読できるようにしておく。
	paths := splitPaths(*pathList)
	if len(paths) == 0 {
		log.Fatalf("-paths が空です")
	}

	stream, err := client.Subscribe(ctx)
	if err != nil {
		log.Fatalf("Subscribe 失敗: %v", err)
	}

	var subs []*gnmipb.Subscription
	for _, p := range paths {
		path, err := ocPath(p)
		if err != nil {
			log.Fatalf("-paths のパスが不正です: %v", err)
		}
		s := &gnmipb.Subscription{
			Path: path,
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

// splitPaths はカンマ区切りのパス指定を分解する。
func splitPaths(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// runCapabilities は Capabilities RPC を呼び，対応モデルとエンコーディングを表示する。
// 出力はバージョン間で diff できるよう名前順に並べる。
func runCapabilities(ctx context.Context, client gnmipb.GNMIClient) error {
	resp, err := client.Capabilities(ctx, &gnmipb.CapabilityRequest{})
	if err != nil {
		return err
	}

	fmt.Printf("gNMI-version: %s\n", resp.GetGNMIVersion())

	encs := make([]string, 0, len(resp.GetSupportedEncodings()))
	for _, e := range resp.GetSupportedEncodings() {
		encs = append(encs, e.String())
	}
	sort.Strings(encs)
	fmt.Printf("encodings: %s\n", strings.Join(encs, ", "))

	models := resp.GetSupportedModels()
	fmt.Printf("models: %d\n", len(models))

	lines := make([]string, 0, len(models))
	for _, m := range models {
		lines = append(lines, fmt.Sprintf("%s\t%s\t%s", m.GetName(), m.GetOrganization(), m.GetVersion()))
	}
	sort.Strings(lines)
	for _, l := range lines {
		fmt.Println(l)
	}
	return nil
}

// probeResult は 1 パスの購読可否。
type probeResult struct {
	path   string
	status string
	detail string
}

// runProbe は候補パスを 1 本ずつ購読して可否を判定する。
//
// Junos は Capabilities でモデルを宣言していても，そのパスのテレメトリ用センサーが
// 実装されていないことがある（例: 実 PFE を持たない vJunos の AFT）。
// モデル宣言では分からないので，実際に Subscribe して応答で判断する。
func runProbe(ctx context.Context, client gnmipb.GNMIClient, paths []string,
	subMode gnmipb.SubscriptionMode, enc gnmipb.Encoding) {

	if len(paths) == 0 {
		log.Fatalf("-probe-paths が空です")
	}

	log.Printf("プローブ開始: %d パス (encoding=%s, mode=%s, timeout=%s/パス)",
		len(paths), *encoding, *mode, *probeTimeout)

	results := make([]probeResult, 0, len(paths))
	for _, p := range paths {
		results = append(results, probeOne(ctx, client, p, subMode, enc))
	}

	fmt.Printf("\n%-12s %s\n", "STATUS", "PATH")
	for _, r := range results {
		fmt.Printf("%-12s %s\n", r.status, r.path)
		if r.detail != "" {
			fmt.Printf("%-12s   %s\n", "", r.detail)
		}
	}
}

// probeOne は 1 パスだけを購読し，sync_response が返れば購読可能と判定する。
func probeOne(ctx context.Context, client gnmipb.GNMIClient, path string,
	subMode gnmipb.SubscriptionMode, enc gnmipb.Encoding) probeResult {

	// フルルートを持つルータで初期同期を受けると膨大になるため，
	// プローブでは -updates-only の指定によらず必ず初期同期を省略する。
	pctx, cancel := context.WithTimeout(ctx, *probeTimeout)
	defer cancel()

	stream, err := client.Subscribe(pctx)
	if err != nil {
		return probeResult{path: path, status: "ERROR", detail: err.Error()}
	}

	gnmiPath, err := ocPath(path)
	if err != nil {
		return probeResult{path: path, status: "ERROR", detail: fmt.Sprintf("不正なパス: %v", err)}
	}
	sub := &gnmipb.Subscription{Path: gnmiPath, Mode: subMode}
	switch subMode {
	case gnmipb.SubscriptionMode_SAMPLE:
		sub.SampleInterval = uint64(*sampleInterval)
	case gnmipb.SubscriptionMode_ON_CHANGE:
		sub.HeartbeatInterval = uint64(*heartbeat)
	}

	req := &gnmipb.SubscribeRequest{
		Request: &gnmipb.SubscribeRequest_Subscribe{
			Subscribe: &gnmipb.SubscriptionList{
				Mode:         gnmipb.SubscriptionList_STREAM,
				Encoding:     enc,
				UpdatesOnly:  true,
				Subscription: []*gnmipb.Subscription{sub},
			},
		},
	}
	if err := stream.Send(req); err != nil {
		return probeResult{path: path, status: "ERROR", detail: err.Error()}
	}

	for {
		resp, err := stream.Recv()
		if err != nil {
			return classifyProbeError(path, err)
		}
		// sync_response が返れば，その時点で購読は受理されている。
		if resp.GetSyncResponse() {
			return probeResult{path: path, status: "OK"}
		}
		// updates_only を無視して初期同期を送ってくる実装もある。
		// データが届いた時点で購読可能と判断してよい。
		return probeResult{path: path, status: "OK", detail: "初期同期あり（updates_only が無視された）"}
	}
}

// classifyProbeError はストリームのエラーを判定結果に変換する。
func classifyProbeError(path string, err error) probeResult {
	st, ok := status.FromError(err)
	if !ok {
		return probeResult{path: path, status: "ERROR", detail: err.Error()}
	}
	switch st.Code() {
	case codes.InvalidArgument:
		return probeResult{path: path, status: "UNSUPPORTED", detail: st.Message()}
	case codes.DeadlineExceeded:
		// 受理されたが更新が無いまま時間切れ，という可能性もある。
		return probeResult{path: path, status: "TIMEOUT", detail: "応答なし（sync_response が返らない）"}
	default:
		return probeResult{path: path, status: "ERROR", detail: fmt.Sprintf("%s: %s", st.Code(), st.Message())}
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

// validateSubscriptionDurations は gNMI の uint64 nanoseconds に変換する値を検証する。
func validateSubscriptionDurations() error {
	if *sampleInterval <= 0 {
		return fmt.Errorf("-sample-interval は 0 より大きくしてください")
	}
	if *heartbeat < 0 {
		return fmt.Errorf("-heartbeat は 0 以上にしてください")
	}
	if *probeTimeout <= 0 {
		return fmt.Errorf("-probe-timeout は 0 より大きくしてください")
	}
	return nil
}

// ocPath は OpenConfig のパス文字列を gnmi.Path に変換する。リストキーは
// element[key=value] の形で指定できる。キー値に含まれる / は角括弧内で扱う。
func ocPath(s string) (*gnmipb.Path, error) {
	var elems []*gnmipb.PathElem
	segments, err := splitPathSegments(s)
	if err != nil {
		return nil, err
	}
	for _, seg := range segments {
		if seg != "" {
			elem, err := parsePathElem(seg)
			if err != nil {
				return nil, err
			}
			elems = append(elems, elem)
		}
	}
	if len(elems) == 0 {
		return nil, fmt.Errorf("パスが空です")
	}
	return &gnmipb.Path{Elem: elems}, nil
}

func splitPathSegments(s string) ([]string, error) {
	s = strings.TrimPrefix(s, "/")
	var segments []string
	start, depth := 0, 0
	for i, r := range s {
		switch r {
		case '[':
			depth++
		case ']':
			depth--
			if depth < 0 {
				return nil, fmt.Errorf("閉じ角括弧の位置が不正です: %q", s)
			}
		case '/':
			if depth == 0 {
				segments = append(segments, s[start:i])
				start = i + 1
			}
		}
	}
	if depth != 0 {
		return nil, fmt.Errorf("角括弧が閉じていません: %q", s)
	}
	segments = append(segments, s[start:])
	return segments, nil
}

func parsePathElem(segment string) (*gnmipb.PathElem, error) {
	keyStart := strings.IndexByte(segment, '[')
	name := segment
	if keyStart >= 0 {
		name = segment[:keyStart]
	}
	if name == "" {
		return nil, fmt.Errorf("要素名がありません: %q", segment)
	}
	if keyStart < 0 {
		return &gnmipb.PathElem{Name: name}, nil
	}

	elem := &gnmipb.PathElem{Name: name, Key: make(map[string]string)}
	predicates := segment[keyStart:]
	for predicates != "" {
		if !strings.HasPrefix(predicates, "[") {
			return nil, fmt.Errorf("キー指定の形式が不正です: %q", segment)
		}
		end := strings.IndexByte(predicates, ']')
		if end < 0 {
			return nil, fmt.Errorf("キー指定が閉じていません: %q", segment)
		}
		predicate := predicates[1:end]
		key, value, ok := strings.Cut(predicate, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("キー指定は key=value 形式にしてください: %q", segment)
		}
		if _, duplicate := elem.Key[key]; duplicate {
			return nil, fmt.Errorf("キー %q が重複しています: %q", key, segment)
		}
		elem.Key[key] = value
		predicates = predicates[end+1:]
	}
	return elem, nil
}
