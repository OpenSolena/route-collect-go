package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"strings"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

var (
	target   = flag.String("target", "localhost:32767", "gNMI ターゲット (host:port)")
	username = flag.String("username", "", "認証ユーザー名")
	password = flag.String("password", "", "認証パスワード")
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

	req := &gnmipb.SubscribeRequest{
		Request: &gnmipb.SubscribeRequest_Subscribe{
			Subscribe: &gnmipb.SubscriptionList{
				Mode: gnmipb.SubscriptionList_STREAM,
				Subscription: []*gnmipb.Subscription{
					{
						Path: ocPath("/network-instances/network-instance/afts"),
						Mode: gnmipb.SubscriptionMode_TARGET_DEFINED,
					},
					{
						Path: ocPath("/network-instances/network-instance/protocols/protocol/bgp"),
						Mode: gnmipb.SubscriptionMode_TARGET_DEFINED,
					},
				},
			},
		},
	}

	if err := stream.Send(req); err != nil {
		log.Fatalf("SubscribeRequest 送信失敗: %v", err)
	}

	log.Printf("Subscribe 開始。更新を待機中...")

	for {
		resp, err := stream.Recv()
		if err != nil {
			log.Fatalf("ストリームエラー: %v", err)
		}
		fmt.Printf("%v\n", resp)
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
