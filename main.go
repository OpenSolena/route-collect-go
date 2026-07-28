package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

var (
	target   = flag.String("target", "localhost:32767", "gNMI ターゲット (host:port)")
	username = flag.String("username", "", "認証ユーザー名")
	password = flag.String("password", "", "認証パスワード")

	// updatesOnly は初期同期（現在の全状態のダンプ）を抑止する。
	// フルルートを持つルータでは初期同期が巨大になるため既定で有効。
	updatesOnly = flag.Bool("updates-only", true, "初期同期を省略し，以降の更新のみ受信する")
	mode        = flag.String("mode", "onchange", "サブスクリプションモード: onchange | sample")
	// sample モードは毎インターバルで全状態を送るため，updates-only は初回しか効かない。
	sampleInterval = flag.Duration("sample-interval", 20*time.Second, "sample モード時の送信間隔")
	heartbeat      = flag.Duration("heartbeat", 0, "onchange モード時のハートビート間隔（0 で無効）")
)

// Junos の gNMI デフォルトポートは 32767
// 本番では TLS を使うこと（insecure.NewCredentials() を置き換える）

func main() {
	flag.Parse()

	conn, err := grpc.NewClient(
		*target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("接続失敗: %v", err)
	}
	defer conn.Close()

	client := gnmipb.NewGNMIClient(conn)

	ctx := metadata.AppendToOutgoingContext(context.Background(),
		"username", *username,
		"password", *password,
	)

	stream, err := client.Subscribe(ctx)
	if err != nil {
		log.Fatalf("Subscribe 失敗: %v", err)
	}

	subMode, err := subscriptionMode(*mode)
	if err != nil {
		log.Fatalf("%v", err)
	}

	paths := []string{
		"/network-instances/network-instance/afts",
		"/network-instances/network-instance/protocols/protocol/bgp",
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
				UpdatesOnly:  *updatesOnly,
				Subscription: subs,
			},
		},
	}

	if err := stream.Send(req); err != nil {
		log.Fatalf("SubscribeRequest 送信失敗: %v", err)
	}

	if *updatesOnly {
		log.Printf("Subscribe 開始（mode=%s, 初期同期なし）。sync_response を待機中...", *mode)
	} else {
		log.Printf("Subscribe 開始（mode=%s, 初期同期あり）。更新を待機中...", *mode)
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
