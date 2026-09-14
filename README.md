<div align="center">

<img src="public/avatar.webp" alt="Chitanda" width="120" />

# **Chitanda (千反田)**

### 高性能・探知耐性プライベートセキュア転送プロトコル

[![Release](https://img.shields.io/github/v/release/violetaini/chitanda?style=flat-square)](https://github.com/violetaini/chitanda/releases)
[![License](https://img.shields.io/badge/License-PolyForm_Noncommercial_1.0.0-orange.svg?style=flat-square)](LICENSE)

</div>


Chitanda は、セルフホスト（自前運用）サーバー環境向けに設計された、高パフォーマンスかつ探知耐性（Anti-Probing）に優れた Go 言語製プロキシ転送プロトコルです。モジュール化されたサーバー実装、組み込み可能なクライアント SDK（Go 標準の `net.Conn` および `net.PacketConn` インターフェースを提供）、およびダイレクト接続用ベンチマークツールを備えています。

現在、メインラインでは **5 種類のトランスポートキャリア（Transport Carriers）** をサポートしています。パブリックインターネット向け推奨の **`h2`（TLS 1.3 + HTTP/2 ストリーム多重化）**、IEPL / IPLC 専用線・高速中継向けに限界スループットを追求した **`stream`（RawStream 独自 TCP）**、さらに **`h3`**、**`auto`**、および IP 直指定モード **`h1`**（エイリアス: `plain-h1`）を提供します。

- 📖 **[詳細設定マニュアル・仕様書 (docs/CONFIGURATION.md)](docs/CONFIGURATION.md)**
- ⚡ **[5大トランスポートモード仕様 (TRANSPORT_MODES.md)](TRANSPORT_MODES.md)**
- 📁 **[設定例ディレクトリ (Examples)](examples/)**
- 📦 **[GitHub 自動ビルドバイナリ (Releases)](https://github.com/violetaini/chitanda/releases)**

---

## 1. トランスポートキャリア・マトリクス (Transport Carrier Matrix)

```text
                             アプリケーション層 / プロキシコア / クライアント SDK
                                                  │
                                            pkg/client SDK
                      ┌───────────────────────────┼───────────────────────────┐
                      ▼                           ▼                           ▼
            【TLS / ドメイン（公網推奨）】     【専用線 / 高速中継（高スループット）】   【IP直指定 / 証明書不要（実験的）】
               h2 (推奨) / h3 / auto                    stream                         h1 (plain-h1)
    ┌─────────────────┬──────────────────┐ ┌──────────────────────────┐ ┌───────────────────────┬───────────────────────┐
    │ TCP: H2/H3 多重化 │ UDP: H3 Datagram │ │ TCP: RawStream (AES-GCM) │ │ TCP: H1 全二重 AEAD   │ UDP: Plain-UDP Datagram│
    └─────────────────┴──────────────────┘ └─────────────┬────────────┘ └───────────────────────┴───────────────────────┘
                      │                                  │                                       │
                      └──────────────────────────────────┼───────────────────────────────────────┘
                                                         ▼
                                                cmd/chitanda-server
```

| モード | TCP 転送方式 | UDP 転送方式 | 0-RTT 対応 | 主な特徴と推奨ユースケース |
| :--- | :--- | :--- | :---: | :--- |
| **`h2`** | TLS 1.3 + HTTP/2 多重化 | H3 QUIC Datagram (RFC 9221) | ✅ (プール流用 0-RTT) | **パブリックインターネット推奨**。単一/複数 TCP 物理接続のコネクションプール多重化。高スループット、極めて低い CPU 負荷、成熟した検閲耐性を実現。 |
| **`stream`** | RawStream TCP (AES-128-GCM) | `plain-udp` ネイティブ AEAD データグラム | ✅ (0-RTT OPEN 動的パディング) | **IEPL / IPLC 専用線および高速中継推奨**。シングルスレッドで最大 2,000 MB/s（ヒープ割り当てゼロ）のスループット。アクティブプローブ完全無効化（未認証プローブは即座に切断、Web 応答なし）。ServerID によるクロスノードリプレイ攻撃防御。 |
| **`h3`** | TLS 1.3 + QUIC Stream + HTTP/3 | H3 QUIC Datagram (RFC 9221) | ✅ (セッション再開 0-RTT) | ネイティブ QUIC による Head-of-Line ブロッキング完全排除。パケットロスや不安定なネットワーク環境への耐性。永続化 Session Ticket 0-RTT に対応。 |
| **`auto`** | H2 優先 $\leftrightarrow$ 障害時自動 H3 フォールバック | H3 QUIC Datagram (RFC 9221) | ✅ | 新規接続時の動的ヘルスチェック。TCP 遮断やパケットロス悪化時にシームレスに H3 へ切り替え。 |
| **`h1`** *(別名 `plain-h1`)* | IP 直指定 HTTP/1.1 全二重 + PSK-AEAD | `plain-udp` ネイティブ AEAD データグラム | ✅ (Flight 1 事前導出 0-RTT) | **ドメイン・証明書不要の IP 直指定実験モード**。TLS オーバーヘッドなしの内層ストリーム認証暗号化。外観は標準的な全二重 HTTP/1.1 に偽装。 |

---

## 2. コアアーキテクチャと暗号設計

### A. TLS 転送メインライン (`h2` / `h3` / `auto`)
- **ハンドシェイクと認証**: TLS 1.3 標準ハンドシェイク（厳格な SNI 検証 / Strict SNI に対応）。
- **Transcript V2 HMAC 署名**: リクエストヘッダーに事前共有鍵（PSK）と長さプレフィックスによるドメイン分離（Domain Separation）を適用した HMAC-SHA256 署名を付与し、Method、Path、Target、Timestamp、Nonce を相互バインド。
- **2ms Group-Commit によるリプレイ攻撃防御**: サーバー側の永続化 Nonce キャッシュは、マイクロバッチ非同期ディスクフラッシュと条件変数（CondVar）起床メカニズムを採用。クラッシュ整合性を保証しつつ、高並行時のディスク I/O ボトルネックを排除。
- **ネイティブ UDP バイパス**: UDP トラフィックは独立した HTTP/3 Extended CONNECT および QUIC Datagram を通じて転送され、2048 ビットのスライディングビットマップによりパケットの順序逆転やリプレイを防御。
- **RFC 7540 HTTP/2 動的フレームパディング注入 (Dynamic Frame Padding)**: `h2` および `auto` モードにおいて、クライアントは HTTP/2 の HEADERS および DATA フレームに 8〜64 バイトのランダム長を持つ RFC 7540 規格準拠のパディングを動的注入。HTTP/2 フロー制御（Flow Control）と厳格に同期し、未消費のクォータはコネクションおよびストリームウィンドウへ自動返却。内層の平文長と外層の TLS レコード長の 1:1 相関関係を完全に破壊し、パケット長解析（パッシブフィンガープリンティング）を無効化。
- **厳格な証明書検証と偽造防止**: Xray クライアントはデフォルトでサーバーの TLS 証明書および公開鍵チェーンの検証を強制し、非 PSK 偽サーバーによるなりすましを排除。自己署名証明書環境向けに明示的な `allow_insecure` 設定を提供。Protobuf 定義を完全更新し、`server_id`、`replay_file`、`allow_insecure` のクロスノードデシリアライズ損失をゼロに抑制。
- **SO_REUSEPORT によるマルチコア並列リッスン (Linux Multi-Core Scaling)**: Linux 本番環境ではサーバーが自動的に `SO_REUSEPORT` を有効化し、CPU コア数に応じた独立したマルチワーカーリスナーをバインド。Linux カーネルのネットワークスタック層で直接コネクションの負荷分散を行い、高並行環境における Accept-Mutex のロック競合ボトルネックを排除。
- **Wire-Version 双方向互換性**: サーバーは最新のネイティブストリームクライアントと、独自のフレーム識別子（`X-Framing: 1`）を持つレガシークライアントを自動認識し、スムーズな下位互換性を確保。

### B. 専用線向け超高速キャリア (`stream` / Chitanda RawStream)
- **多相的離散ハンドシェイクとプローブオラクル排除 (Polymorphic Discrete Handshake & Zero Probe Oracle)**:
  - 固定ハンドシェイクパケット長のシグネチャを完全に排除。ClientHello の長さを 49〜113 バイト、ServerHello の長さを 41〜105 バイトに離散化。
  - コアフレームヘッダー形式は `[1B padLen ^ mask] [8B masked ts] [24B nonce] [16B tag] [padLen padBytes]`。PSK から導出された動的マスクによりタイムスタンプとパディング長を暗号化し、平文ゼロ値（`0x00000000`）の漏洩を完全遮断。
  - サーバーは最初の 49 バイトを読み取り、固定時間（Constant-time）HMAC-SHA256 で完全性と鮮度を検証。1 バイトのアクティブプローブオラクルを排除。未認証トラフィックに対しては即座にコネクションを切断し、0 バイト（無応答）を返送。
- **適応型動的レコードサイジング (Dynamic Record Sizing)**:
  - **低レイテンシ・インタラクティブモード**: 接続確立直後やアイドル時（>100ms 送信なし）は、MTU に最適化されたサイズ（1,418 バイト単位）で自動フレーム分割。大フレームによるパケット分割やキューイング遅延を解消し、Web 閲覧や API コールにおける TTFB（Time to First Byte）を 50% 以上短縮。
  - **限界バルクスループットモード**: 継続的なバーストトラフィック（累積送信量 >128KB）を検出すると、フレームウィンドウを 32KB（MaxChunkLen）まで自動かつ滑らかに拡大。シングルスレッドでのスループットは最大 **31.7 Gbps (3,962.5 MB/s)** に達し、かつ究極のヒープメモリ割り当てゼロ（0 allocs/op）を維持。
- **0-RTT 動的難読化ファーストフライトと優雅なハーフクローズ (Half-Close)**:
  - 0-RTT OPEN ターゲットフレームに 32〜256 バイトの動的ランダムパディングを強制注入し、初期パケット長のフィンガープリントを平滑化。
  - サーバー側で 2 フェーズコミット（Two-Phase Commit）型の永続化 Nonce キャッシュを採用（ClientHello + 0-RTT フレームの復号成功後に初めてディスク永続化を実行）。リプレイ攻撃によるキャッシュ汚染や、再起動・ノード間をまたぐリプレイを阻止。
  - TCP 全二重通信およびハーフクローズ（Half-Close）の協調を厳格にサポート。大容量ファイルの片方向ストリーミング通信にも完全対応。
- **DPI・アクティブプローブ耐性**:
  - 未認証トラフィック（スキャナーによる `GET / HTTP/1.1` や不正プローブパケットなど）を検知した場合、**即座に接続を切断して 0 バイトを返却。HTTP/Web エラー応答などの指紋は一切返送しない**。

### C. IP 直指定・実験的キャリア (`h1` / `plain-udp`)
- **標準全二重 HTTP/1.1 キャリア (`h1`)**:
  - 外層には標準的な `POST <path> HTTP/1.1` および `Transfer-Encoding: chunked` のみを使用し、サーバー側で全二重ストリーミングを有効化。
  - 0-RTT OPEN ターゲットフレームは Flight 1 パケットに統合して送信され、ターゲットへの即時接続を確立。
  - チャンクストリームリーダーは最大 64KB の正規大ブロックデータ転送を完全サポート。パケット分断によるデータ切り捨てを防ぎ、未認証の過大なメモリ割り当て（OOM）を防止。
- **`plain-udp` ネイティブ AEAD データグラムと完全暗号化高エントロピーペイロード**:
  - **完全暗号化・平文フィンガープリントゼロ**: 外層パケットは `[24B Crypto Nonce] [AEAD Ciphertext + 16B Tag]` のみで構成。SessionID、単調増加シーケンス番号（Seq）、タイムスタンプ、データペイロードのすべてが XChaCha20-Poly1305 暗号文内にカプセル化。外層シャノンエントロピーは **7.996+ bits/byte**（理論上限 8.0 に極めて近い）に達し、シーケンス番号や平文ヘッダーの特徴を完全に排除。
  - **双方向個別鍵と反射攻撃防御**: `c2sKey` と `s2cKey` を個別に導出。Associated Data（AD）に転送方向（`DirClientToServer` / `DirServerToClient`）を強制バインドし、反射されたパケットの復号は即座に失敗。
  - **リプレイ防御とパケット順序逆転の許容**: サーバー側で 2048 ビットのスライディングビットマップを保持してリプレイを検知・防御。最大 120 秒のタイムスタンプドリフト保護をサポート。
  - **クライアント送信元検証と並行安全性**: クライアントは対向 IP/Port が正規サーバーアドレスであることを厳格に検証。内部で独立したメモリプールを採用し、`net.PacketConn` のスレッドセーフな並行呼び出しを保証。
  - **サーバーリソース境界管理**: サーバー全体の最大アクティブセッション数（10,000）およびセッションあたりの最大転送ターゲット数（32）を制限し、悪意ある UDP フラッドによるファイルディスクリプタ（FD）やメモリの枯渇を防止。

### D. 多階層フォールバック機構 (Dynamic Masquerade Fallback)
パス不一致、メソッド検証失敗、または HMAC 認証に失敗した HTTP リクエストは、設定に応じて透過的にフォールバック:
1. **内蔵エンタープライズ ERP ゲートウェイ**: Vanguard Global Operations Hub (EBG v4.2) レスポンシブポータルおよび REST API を内蔵。
2. **ローカル静的ディレクトリ**: 指定された HTML/静的アセットをホスティング。
3. **Nginx UDS リバースプロキシ**: `unix:/path/to/nginx.sock` 経由でネットワークスタックのオーバーヘッドなしにローカル Web サービスへプロキシ。
4. **ローカルポートリバースプロキシ**: `127.0.0.1:8080` などのローカル HTTP サービスへ転送。

### E. 全モード共通のハーフクローズとミリ秒単位の優雅なリソース回収 (Half-Close & Graceful Drain)
- **高頻度ショートコネクションおよびスマホゲーム向け切断防止最適化**: 『ブルーアーカイブ』などの高頻度・バースト的なショート通信を行うモバイルゲームや Web API ポーリングを想定し、宛先サーバーのレスポンスが完了して切断された際（`downloadDone`）、サーバー側で **250ms 高速回収メカニズム** を一元的に実行。
- **インバンド EOF マーカーと双方向ソケットの確実な解放**:
  - `stream` モード: サーバーからクライアントへインバンドの `[0x00, 0x00]` ゼロ長フレームマーカーを送信し、TCP FIN を付与。クライアントはこれを受信後、即座にローカルアップストリームをクローズ。
  - `h3` モード: タイムアウト時に能動的に `stream.CancelRead(0)` をトリガーし、ハングした QUIC ストリームを強制終了。ストリーム上限到達によるスタックを排除。
  - `h2` および `h1` モード: 従来の 30 秒の冗長な待機時間を 250ms に大幅短縮し、リード用 Goroutine がハングした場合はソケットを直接切断。
- **ファイルディスクリプタ (FD) リークの完全解消**: 50 以上の並行ショートリクエストによる実測検証において、すべてのソケットが 325ms 以内に完全解放され、**ソケットの残留はゼロ。OpenClash 等のソフトルーターにおける 9090 コントロールポートの無応答（ハング）や DNS タイムアウトを根本から解決**。

### F. クライアントの Zero-DefaultResolver 規約と Mihomo ネイティブ名前解決連携
- **クライアントの防護的クラッシュ (`os.Exit(2)`) の根絶**: Mihomo (Clash.Meta) コアでは、プロキシのアウトバウンドが Go 標準ライブラリのシステム DNS リゾルバを直接呼び出すことを固く禁止しており（違反時は即座に `os.Exit(2)` でプロセス終了）、Chitanda クライアント SDK は Zero-DefaultResolver 規約を徹底。パケットの逆引き・解析はすべて `netip.ParseAddrPort` および `net.ParseIP` によるロックフリーなインメモリ処理で実行。
- **Mihomo ネイティブ名前解決とポリシールーティングの協調**: ノードのドメイン解決は Mihomo の `ProxyServerHostResolver` に完全委譲。UDP トンネル確立時には `c.dialer.ListenPacket` にリモート宛先 `AddrPort` を明示的に注入し、Linux ルーター環境における `fwmark` ルーティングポリシーと NIC バインドが 100% 正確にヒットすることを保証。

### G. Shadowsocks スタイルの双方向アクティビティ連動アイドルタイムアウト (Shadowsocks-Style Activity Idle Timeout)
- **大規模言語モデル（LLM / Codex / ChatGPT SSE）の長時間ストリーミングに完全対応**: 数 MB に及ぶ巨大プロンプト（Context）送信完了後、推論・思考・逐次トークン出力（SSE）が数分間に及ぶシナリオにおいて、従来のクライアント送信完了（`uploadDone`）後 60 秒での一律強制切断を完全撤廃。
- **双方向アクティビティ監視（`activityReader`）と動的自律更新**: 上り（クライアント $\to$ ターゲット）または下り（ターゲット $\to$ クライアント）のいずれかの方向で 1 バイトでもパケットが流れている限り、アイドルタイマー（`DefaultIdleTimeout = 300s`）を動的に自動リセット。
- **5大トランスポートモード全対応**: `stream`、`h2`、`h3`、`auto`、`h1`（`plain-h1`）の全キャリアで完全に対称実装。両方向が 300 秒間完全に無通信（完全な静黙）となった場合のみ安全にタイムアウト切断。
- **長時間のストリーミング推論と高頻度ゲーム通信の高度な両立**: 宛先切断時の 250ms 高速ドレインと協調動作し、「LLM の長文推論が途中で切断されない安定性」と「ゲーム高頻度リクエスト時の FD 枯渇防止」を両立。

---

## 3. Go SDK 利用例

```go
package main

import (
	"context"
	"log"
	"net"
	"time"

	"github.com/violetaini/chitanda/pkg/client"
)

func main() {
	// デフォルト推奨: h2 (TLS 1.3 多重化メインライン)
	cli, err := client.New(client.Config{
		Server:       "server.example.com:443",
		ServerName:   "server.example.com",
		PSK:          []byte("your-32-byte-secure-pre-shared-key-here"),
		Path:         "/api/v1/sync",
		TCPTransport: client.TCPTransportH2, // モード: "h2", "stream", "h3", "auto", "h1"
	})
	if err != nil {
		log.Fatalf("Init client failed: %v", err)
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. TCP アウトバウンドダイヤル (標準 net.Conn を返却)
	tcpConn, err := cli.DialContext(ctx, "tcp", "www.google.com:443")
	if err != nil {
		log.Fatalf("Dial TCP failed: %v", err)
	}
	defer tcpConn.Close()

	// 2. ネイティブ UDP アウトバウンドリスナー (標準 net.PacketConn を返却)
	udpConn, err := cli.ListenPacket(ctx)
	if err != nil {
		log.Fatalf("Listen UDP failed: %v", err)
	}
	defer udpConn.Close()

	dnsServer, _ := net.ResolveUDPAddr("udp", "1.1.1.1:53")
	dnsQuery := []byte{ /* ... DNS Wire Query ... */ }
	_, _ = udpConn.WriteTo(dnsQuery, dnsServer)
}
```

---

## 4. クライアント・サーバー設定例 (Mihomo & Xray-core)

詳細なパラメーターリファレンスと本番アーキテクチャについては **[docs/CONFIGURATION.md](docs/CONFIGURATION.md)** を参照してください。

### A. Mihomo (Clash.Meta) クライアント 5 モード設定例

Mihomo の `config.yaml` 内の `proxies` リストに直接指定します：

```yaml
proxies:
  # モード 1: H2 多重化モード (TLS 1.3 + HTTP/2 ストリーム多重化) - 公開ネットワーク推奨
  - name: "Chitanda-H2-Tokyo"
    type: chitanda
    server: jp.example.com
    port: 443
    psk: "your-32-byte-secure-pre-shared-key-here"
    path: "/api/v1/sync"
    transport: "h2"
    sni: "jp.example.com"
    pool-size: 4
    udp: true

  # モード 2: Stream 専用線高スループットモード (RawStream TCP + AES-128-GCM + 動的難読化) - 専用線推奨
  - name: "Chitanda-Stream-Tokyo"
    type: chitanda
    server: 203.0.113.88
    port: 11323
    psk: "your-32-byte-secure-pre-shared-key-here"
    transport: "stream"
    server-id: "tokyo-node-01"
    udp: true

  # モード 3: H3 ネイティブ QUIC モード (HTTP/3 0-RTT + Head-of-Line ブロッキングなし)
  - name: "Chitanda-H3-Tokyo"
    type: chitanda
    server: jp.example.com
    port: 443
    psk: "your-32-byte-secure-pre-shared-key-here"
    path: "/api/v1/sync"
    transport: "h3"
    sni: "jp.example.com"
    udp: true

  # モード 4: Auto インテリジェント自己治癒モード (H2 主線 + 障害時 H3 へフォールバック)
  - name: "Chitanda-Auto-Tokyo"
    type: chitanda
    server: jp.example.com
    port: 443
    psk: "your-32-byte-secure-pre-shared-key-here"
    path: "/api/v1/sync"
    transport: "auto"
    sni: "jp.example.com"
    pool-size: 4
    udp: true

  # モード 5: H1 IP 直指定・証明書不要実験モード (全二重 HTTP/1.1 AEAD + Plain-UDP)
  - name: "Chitanda-H1-DirectIP"
    type: chitanda
    server: 203.0.113.88
    port: 18200
    psk: "your-32-byte-secure-pre-shared-key-here"
    path: "/gateway/stream/v2"
    transport: "h1"
    udp: true
```

完全な設定テンプレートは **[examples/mihomo/config.yaml](examples/mihomo/config.yaml)** を参照してください。

---

### B. Xray-core サーバー・クライアント 5 モード設定例

#### 1) サーバー側インバウンド設定 (`inbounds`)
```json
{
  "inbounds": [
    {
      "tag": "chitanda-h2-in",
      "port": 443,
      "protocol": "chitanda",
      "settings": {
        "psk": "your-32-byte-secure-pre-shared-key-here",
        "path": "/api/v1/sync",
        "transport": "h2",
        "strict_sni": "jp.example.com",
        "fallback": "127.0.0.1:8080"
      },
      "streamSettings": {
        "security": "tls",
        "tlsSettings": {
          "certificates": [{ "certificateFile": "/etc/ssl/cert.pem", "keyFile": "/etc/ssl/key.pem" }]
        }
      }
    },
    {
      "tag": "chitanda-stream-in",
      "port": 11323,
      "protocol": "chitanda",
      "settings": {
        "psk": "your-32-byte-secure-pre-shared-key-here",
        "server_id": "tokyo-node-01",
        "transport": "stream",
        "replay_file": "/etc/x-ui/replay_11323.db"
      },
      "streamSettings": { "security": "none" }
    },
    {
      "tag": "chitanda-h1-in",
      "port": 18200,
      "protocol": "chitanda",
      "settings": {
        "psk": "your-32-byte-secure-pre-shared-key-here",
        "path": "/gateway/stream/v2",
        "transport": "h1",
        "fallback": "127.0.0.1:80"
      },
      "streamSettings": { "security": "none" }
    }
  ]
}
```

#### 2) クライアント側アウトバウンド設定 (`outbounds`)
```json
{
  "outbounds": [
    {
      "tag": "chitanda-h2-out",
      "protocol": "chitanda",
      "settings": {
        "server": "jp.example.com:443",
        "server_name": "jp.example.com",
        "psk": "your-32-byte-secure-pre-shared-key-here",
        "path": "/api/v1/sync",
        "transport": "h2",
        "pool_size": 4,
        "allow_insecure": false
      }
    },
    {
      "tag": "chitanda-stream-out",
      "protocol": "chitanda",
      "settings": {
        "server": "203.0.113.88:11323",
        "psk": "your-32-byte-secure-pre-shared-key-here",
        "server_id": "tokyo-node-01",
        "transport": "stream"
      }
    },
    {
      "tag": "chitanda-h3-out",
      "protocol": "chitanda",
      "settings": {
        "server": "jp.example.com:443",
        "server_name": "jp.example.com",
        "psk": "your-32-byte-secure-pre-shared-key-here",
        "path": "/api/v1/sync",
        "transport": "h3",
        "allow_insecure": false
      }
    },
    {
      "tag": "chitanda-auto-out",
      "protocol": "chitanda",
      "settings": {
        "server": "jp.example.com:443",
        "server_name": "jp.example.com",
        "psk": "your-32-byte-secure-pre-shared-key-here",
        "path": "/api/v1/sync",
        "transport": "auto",
        "pool_size": 4,
        "allow_insecure": false
      }
    },
    {
      "tag": "chitanda-h1-out",
      "protocol": "chitanda",
      "settings": {
        "server": "203.0.113.88:18200",
        "psk": "your-32-byte-secure-pre-shared-key-here",
        "path": "/gateway/stream/v2",
        "transport": "h1"
      }
    }
  ]
}
```

完全なサーバーおよびクライアントの JSON ファイルは **[examples/xray/server_all_modes.json](examples/xray/server_all_modes.json)** および **[examples/xray/client_all_modes.json](examples/xray/client_all_modes.json)** を参照してください。

---

## 5. アップストリーム追従・自動 CI/CD パイプライン (Automated Upstream CI/CD)

本リポジトリの GitHub Actions ワークフロー (`.github/workflows/upstream-sync-build.yml`) により、以下の処理が完全自動化されています：
1. **自動監視**: `XTLS/Xray-core` および `MetaCubeX/mihomo` の最新リリースタグを毎日定期ポーリング。
2. **動的インジェクション**: `scripts/inject-xray.py` および `scripts/inject-mihomo.py` を実行し、非侵襲的にアダプターをマウント。
3. **マルチプラットフォーム自動リリース**: Windows / Linux / macOS の各 CPU アーキテクチャ向けバイナリを自動クロスコンパイルし、本リポジトリの [GitHub Releases](https://github.com/violetaini/chitanda/releases) に直接発行。

---

## 6. 3X-UI カスタム版ワンクリックデプロイ (3X-UI v2.3.11 with Chitanda Core)

本プロジェクトの専用ブランチ [`3x-ui`](https://github.com/violetaini/chitanda/tree/3x-ui) では、カスタマイズ版の **3X-UI (v2.3.11)** コントロールパネルを提供しています。実績のある堅牢な v2.3.11 アーキテクチャをベースに、カーネルのダウンロード元および更新インターフェースをシームレスに Chitanda Xray-core へリダイレクトしています。

### ワンクリックインストールコマンド

Linux サーバー（Ubuntu / Debian / CentOS / AlmaLinux 等）にて root 権限で実行します：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/violetaini/chitanda/3x-ui/install.sh)
```

### 主な機能と特徴
- **即時利用可能**: 3X-UI パネルのインストールから、最新の `xray-chitanda` カーネルの配備までを自動完了。
- **全トランスポートモード対応**: インバウンド設定にて `h2`、`stream`、`h3`、`auto`、`h1` をネイティブ選択可能。証明書不要の `stream` モード選択時は TLS 証明書および SNI フォームを自動非表示化。`server_id` ノード識別バインドおよびポートごとの永続化リプレイ防止 DB（`/etc/x-ui/replay_[ポート].db`）に完全連動。
- **全モード UDP ネイティブ対応**: Xray 原生 Plain-UDP Inbound とアンチリプレイウィンドウを搭載。単一ポートで TCP/UDP 同時待ち受けをサポートし、DNS クエリや UDP ゲーム通信の完全なプロキシに対応。
- **大容量・長ストリーム安定性**: 8 KiB 超過時の書き込みバッファ溢れ（`ErrBufferFull`）を根絶。適応型動的分割（1380 B $\to$ 8 KiB $\to$ 32 KiB）がフル稼働し、単一コア最大 2,000 MB/s 超のスループットと長文 AI ストリーミングの継続性を保証。
- **QR コード表示と一括エクスポート**: インバウンド管理メニューから Chitanda ノードの QR コード確認や一括エクスポート・共有が可能。
- **Web UI 上でのカーネルオンライン更新**: 3X-UI 管理画面の **Xray 設定 → バージョン切り替え** 機能が本リポジトリの GitHub Releases に連携済み。最新の Chitanda Xray カーネルをオンラインで直接選択・ホットアップデート可能。
- **モバイルゲーム・高頻度通信のハング防止**: 最新の 250ms ハーフクローズ優雅排空ライフサイクル制御を搭載。『ブルーアーカイブ』等の高頻度通信によるコネクション滞留、FD リーク、ルーターのフリーズ問題を根本から解消（詳細は [docs/CONFIGURATION.md](docs/CONFIGURATION.md#6-高頻度ショートコネクションとモバイルゲーム向け最適化仕様-half-close--ブルーアーカイブ事例) を参照）。
- **マルチアーキテクチャ対応**: Linux AMD64 (`x86_64`) および ARM64 (`aarch64`) を自動識別・適合。

### 3X-UI Xray カーネルの更新手順 (Updating 3X-UI Xray Kernel)

- **方式 1：Web 面板一键无缝切换（推荐）**
  1. 登录 3X-UI 面板网页后台；
  2. 进入 **面板设置 (Settings) $\rightarrow$ Xray 设置 / 版本控制**；
  3. 版本下拉框已内置对接本仓库，选择最新版本（如 **`v26.3.27`**）点击 **切换版本**，面板全自动下载、解压、覆盖并热重启。

- **方式 2：终端一键更新指令（不用进网页）**
  如果在终端操作，不能只执行 `rm`，而是需要一条龙“下载最新 Release $\rightarrow$ 解压覆盖 $\rightarrow$ 重启”：

  ```bash
  curl -fsSL https://github.com/violetaini/chitanda/releases/download/v26.3.27/Xray-linux-64.zip -o /usr/local/x-ui/bin/Xray.zip && \
  python3 -c "import zipfile, os; zipfile.ZipFile('/usr/local/x-ui/bin/Xray.zip').extract('xray', '/usr/local/x-ui/bin'); os.chmod('/usr/local/x-ui/bin/xray', 0o755); os.replace('/usr/local/x-ui/bin/xray', '/usr/local/x-ui/bin/xray-linux-amd64'); os.remove('/usr/local/x-ui/bin/Xray.zip')" && \
  x-ui restart
  ```

  > **注意**：`x-ui restart` 仅为重启面板服务，**不包含**缺失内核自动下载功能。若直接 `rm -f /usr/local/x-ui/bin/xray-linux-amd64` 后重启，面板会因为找不到二进制文件而提示 `未知版本 + error 运行状态`。请务必使用上述一键更新指令。

---

## 7. モバイルおよびルーターエコシステム統合 (OpenWrt & Android Ecosystem)

Chitanda ノードを各種端末でスムーズに利用できるよう、OpenWrt ソフトウェアルーターおよび Android 端末向けの専用クライアントと自動同期パイプラインを提供しています：

### A. OpenClash ルーター向けカスタム版 (`chitanda-openclash`)
- **リポジトリ**: [`violetaini/chitanda-openclash`](https://github.com/violetaini/chitanda-openclash)
- **カーネル自動リダイレクト**: OpenClash 公式のカーネルダウンロード・オンライン更新パスを Chitanda 専用 `mihomo` リリースへリダイレクト。
- **アクセラレーションミラーと自動リトライ**: `github_address_mod` プロキシロジックを強化し、ネットワーク状況に応じたフェイルオーバーを実装。ルーター上でのワンクリックカーネル更新を安定化。
- **クラッシュ防止と Zero-DefaultResolver 規約**: 高頻度 UDP 通信やドメイン指定ノード利用時に Mihomo の防護的アサーションクラッシュが発生する問題を排除し、OpenClash の 24 時間 365 日の安定稼働を実現。
- **上流自動同期パイプライン**: GitHub Actions により `vernesong/OpenClash` メインラインを定期追従し、最新の LuCI パッケージを自動ビルド・更新。

### B. Clash Meta For Android カスタム版 (`chitanda-cmfa`)
- **リポジトリ**: [`violetaini/chitanda-cmfa`](https://github.com/violetaini/chitanda-cmfa)
- **Chitanda プロトコルネイティブ統合**: Chitanda 拡張コアを組み込んだ `mihomo` モバイルコアをプリインストール。`h2`、`stream`、`h3`、`auto`、`h1` 全モードのノードインポート、スピードテスト、ルーティングに対応。
- **タグ追従・自動ビルド**: `MetaCubeX/ClashMetaForAndroid` 公式リリースタグを監視し、署名鍵およびコードを自動注入した上で最新 APK パッケージをビルド・リリース。

---

## 8. ビルドと検証 (Build & Verification)

```sh
# 全ユニットテストの実行（暗号化、反射攻撃防止、リプレイ攻撃注入、全二重ループバック、UDP シミュレーションを含む）
go test -count=1 -v ./...

# RawStream ゼロコピー・スループット・マイクロベンチマークの実行
go test -bench="." -benchmem github.com/violetaini/chitanda/internal/rawstream

# Linux 本番用バイナリのクロスコンパイル
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/chitanda-server ./cmd/chitanda-server
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/chitanda-client ./cmd/chitanda-client
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/bench-direct ./cmd/bench-direct
```

---

## 9. パフォーマンスベンチマーク (Micro-Benchmarks)

x86_64 (AES-NI ハードウェアアクセラレーション有効) 環境における RawStream および AEADStream の実測ベンチマーク結果：

| ベンチマーク項目 | スループット | 1 回あたりの所要時間 | ヒープ割り当てメモリ | 1 回あたりの割り当て回数 |
| :--- | :---: | :---: | :---: | :---: |
| **`BenchmarkStreamConn_DynamicRecord_BulkThroughput`** | **3,962.50 MB/s (31.7 Gbps)** | 8.2 μs | **0 B/op** | **0 allocs/op** |
| **`BenchmarkStreamConn_Throughput`** | **1,984.90 MB/s (15.8 Gbps)** | 16.5 μs | **0 B/op** | **0 allocs/op** |
| **`BenchmarkAEADStream_Direct`** | **2,194.64 MB/s** | 7.4 μs | **0 B/op** | **0 allocs/op** |
| **`BenchmarkAES128GCM_Direct`** | **2,279.36 MB/s** | 7.1 μs | **0 B/op** | **0 allocs/op** |

*注：全二重ストリーミング転送、動的適応型レコードサイジング（Dynamic Record Sizing）、およびバッチディスクフラッシュにより、完全なヒープ割り当てゼロ（0 allocs/op）を実現。単一接続におけるバルクスループットは最大 31.7 Gbps に達し、ハードウェアバスおよび CPU の AES-NI 命令スループットの物理的限界に迫ります。*

---

## 10. 技術的境界とセキュリティに関する考慮事項 (Threat Model & Limitations)

1. **トランスポートキャリアの適用領域とネットワーク環境**:
   - `h2` / `h3`: TLS 1.3 暗号化および正規 SNI への偽装に依存しており、パブリックインターネットにおける**主力のセキュア通信キャリア**として位置付けられます。
   - `stream` (Chitanda RawStream): HTTP プロトコルの冗長性を完全に排除し、AES-128-GCM + 動的パディングを採用。**IEPL / IPLC 専用線および BGP 中継ネットワーク** に特化して設計されており、超高スループットを実現するとともに、商用 DPI やファイアウォールによるアクティブプローブ（HTTP 嗅探）を遮断します。
   - `h1`: 証明書不要のダイレクト接続および HTTP 偽装能力を備え、IP 直指定やイントラネット貫通トンネルとして機能します。
2. **前方秘匿性（Forward Secrecy）に関する注意事項**:
   - TLS モード (`h2` / `h3`): TLS 1.3 ECDHE に基づく完全な前方秘匿性（PFS）を提供します。
   - 静的 PSK モード (`stream` / `h1` / `plain-udp`): 事前共有鍵（PSK）からセッション鍵を導出するため、エフェメラル鍵交換による PFS は備えていません。機密性の高いパブリックインターネット通信には TLS 1.3 キャリアの使用を推奨します。
3. **0-RTT およびリプレイ攻撃防御**:
   - `stream`: サーバー側で 2 フェーズコミット（Two-Phase Commit）型の永続化リプレイキャッシュを採用し、認証および復号に成功した Nonce のみをディスクへ書き込みます。また、ServerID とバインドすることでノード間をまたぐリプレイ攻撃を防御します。
   - `plain-udp`: XChaCha20-Poly1305（24 バイト Nonce）、双方向で独立した導出鍵（`c2sKey` / `s2cKey`）、および方向識別 AD を採用し、パケット反射攻撃や Nonce のバースデー衝突を完全に防ぎます。

---

## 11. 免責事項および利用規約 (Disclaimer & Terms of Use)

本ソフトウェア（Chitanda およびその関連ツール・コンポーネントを含みます。以下「本ソフトウェア」）をダウンロード、複製、改変、インストール、実行、または利用するすべての利用者（以下「ユーザー」）は、以下の条項を注意深く読み、全面的に同意したものとみなされます。**以下の条項に同意できない場合、または遵守できない場合は、本ソフトウェアを直ちに削除し、一切の利用を中止してください。**

### 1. 学術研究および技術検証目的の限定
本ソフトウェアは、暗号化プロトコルの動作検証、ネットワーク転送効率の研究、高並行通信アーキテクチャの性能評価、および個人的な学術探求のみを目的として公開されています。悪意あるネットワーク攻撃、不正アクセス、検閲回避を目的とした不正な手段の提供、あるいは違法な目的での利用を意図・推奨するものではありません。

### 2. 商用利用の厳格な禁止 (Strict Prohibition of Commercial Use)
本ソフトウェアおよびその派生物は、**非営利かつ個人的な研究・実験目的でのみ利用可能です。**
商用目的での利用（以下を含みますがこれらに限定されません）は固く禁止されています：
- 本ソフトウェアをコア技術として組み込んだ商用 VPN サービス、有償プロキシサービス、ネットワークアクセラレーションサービスの構築・運営・販売。
- 本ソフトウェアまたはカスタマイズ版の有償販売、ライセンス販売、再頒布、またはこれらを通じた直接的・間接的な収益化行為。
- クラウド事業者やホスティングサービス上での有償ノード・回線提供における転用。

### 3. 利用者の居住国・地域における適用法令の遵守 (Compliance with Applicable Laws)
1. **法令遵守義務**: ユーザーは、本ソフトウェアの利用にあたり、自身が居住または滞在する国・地域、およびサーバーや中継ノードが物理的または法的に所在する国・地域のすべての法令、条例、通信規制（電気通信事業法、不正アクセス禁止法、通信の秘密保護法、暗号輸出入管理規制、およびサイバーセキュリティ関連法規を含みますがこれらに限定されません）を自らの責任において完全に遵守しなければなりません。
2. **利用制限および禁止**: **ユーザーが居住または所在する国・地域の法令により、暗号化通信ツールの配備、特定のプロキシプロトコルの利用、またはネットワークトラフィックの迂回・制御が制限または禁止されている場合、ユーザーは本ソフトウェアをダウンロード、インストール、構成、または使用することは一切認められません（直ちに使用を中止してください）。**
3. **違法行為の禁止**: 本ソフトウェアを、不正アクセス、マルウェア配布、DoS/DDoS 攻撃、著作権侵害、詐欺、その他法令または公序良俗に反する行為のために利用することを厳格に禁止します。

### 4. 無保証および責任の制限 (Disclaimer of Warranty & Limitation of Liability)
1. **現状有姿での提供 (AS IS)**: 本ソフトウェアは「現状有姿」（AS IS）かつ「提供可能な限度」で提供され、商品性、特定目的への適合性、権利の非侵害性、動作の完全性、セキュリティ、エラーや脆弱性の不存在を含め、明示的または黙示的を問わず、いかなる種類の保証も行われません。
2. **責任の否認**: 本ソフトウェアの開発者、メンテナー、および貢献者は、本ソフトウェアの利用、誤用、または利用不能から生じたいかなる損害（直接損害、間接損害、特別損害、付随的損害、派生的損害、逸失利益、データ損失、通信機器の障害、行政処分、刑事罰、法的紛争などを含むがこれらに限定されない）に対しても、法的根拠（契約責任、不法行為責任、過失責任など）を問わず、一切の責任を負いません。
3. **自己責任の原則**: 本ソフトウェアの使用に関する一切のリスクは、ユーザー自身が単独で負担するものとします。

### 5. ソースコード利用許諾 (Source Code License)
本プロジェクトのソースコードは、**[PolyForm Noncommercial License 1.0.0](LICENSE)** に基づいて公開・提供されています。
個人による学術研究、非営利目的の実験、学習、および非営利組織での利用に限り、ソースコードの利用、複製、改変、および再頒布が許可されます。いかなる商用利用・営利サービス化も禁止されています。詳細なライセンス条文はリポジトリ直下の [LICENSE](LICENSE) を参照してください。
