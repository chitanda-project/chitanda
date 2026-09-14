# Chitanda プロトコル全モード設定ガイド (Mihomo / Clash.Meta & Xray-core Wiki)

本文書は、**Chitanda (千反田)** 転送プロトコルにおける **Mihomo (Clash.Meta)** クライアントおよび **Xray-core** サーバー／クライアントの完全な設定マニュアルと、5 種類のトランスポートキャリアモード（`h2` / `stream` / `h3` / `auto` / `h1`）の詳細な構成例を提供します。

---

## 1. トランスポートキャリアモード概要 (Transport Matrix)

| モード | トランスポート識別子 | 転送メカニズム (TCP / UDP) | 証明書要件 | 主な推奨ユースケース |
| :--- | :--- | :--- | :---: | :--- |
| **H2 ストリーム多重化** | `h2` | TLS 1.3 + HTTP/2 多重化 / H3 QUIC Datagram | 必須 (有効な TLS 証明書) | **本番パブリック環境推奨**。高並行プール多重化、極めて低い CPU 負荷、成熟した耐検閲性。 |
| **専用線高速ストリーム** | `stream` | RawStream TCP (AES-128-GCM) / `plain-udp` ネイティブ AEAD | **不要 (専用線 / 純 IP)** | **IEPL / IPLC 専用線および高速中継**。シングルスレッド 4,000 MB/s 超、離散ハンドシェイク、アクティブプローブ無応答。 |
| **ネイティブ H3/QUIC** | `h3` | TLS 1.3 + HTTP/3 多重化 / H3 QUIC Datagram | 必須 (有効な TLS 証明書) | **パケットロス・弱網環境**。ネイティブ 0 Head-of-Line ブロッキング、モバイル回線切り替えへの高い耐性。 |
| **自律フェイルオーバー** | `auto` | 動的 H2 優先 $\leftrightarrow$ 障害時自動 H3 降格・自律回復 | 必須 (有効な TLS 証明書) | **混合ネットワーク環境**。動的ヘルスチェックと無瞬断自動フォールバック。 |
| **純 IP 実験的チャネル** | `h1` *(plain-h1)* | 純 IP HTTP/1.1 全二重 AEAD / ネイティブ `plain-udp` | **不要 (純 IP 直接接続)** | **イントラネット / 純 IP 相互接続**。TLS オーバーヘッドゼロ、標準 HTTP バイナリストリームへの静的偽装。 |

---

## 2. Mihomo (Clash.Meta) クライアント設定マニュアル

### 2.1 ノードパラメーター一覧 (Proxy Parameters)

| フィールド | 型 | 必須 | デフォルト値 | 詳細説明 |
| :--- | :---: | :---: | :---: | :--- |
| `name` | String | はい | - | ノードの表示名 |
| `type` | String | はい | - | プロトコル識別子。`chitanda` を固定指定 |
| `server` | String | はい | - | サーバーのホスト名（ドメイン）または IP アドレス |
| `port` | Integer | はい | - | サーバーのリッスンポート (例: `443` または任意のポート) |
| `psk` | String | はい | - | 事前共有鍵 (Pre-Shared Key。サーバー側と完全に一致させる必要があります) |
| `path` | String | いいえ | `/api/v1/sync` | 偽装リクエストパス。一般的な API パスを推奨 (`stream` モードでは不要) |
| `transport` | String | いいえ | `h2` | キャリアモード: `h2` (デフォルト)、`stream`、`h3`、`auto`、`h1` (または `plain-h1`) |
| `sni` | String | いいえ | (`server` と同一) | TLS SNI ドメイン。TLS モードでは有効なドメインが必須、`stream`/`h1` モードでは省略可 |
| `server-id` | String | いいえ | - | サーバーノード識別子 (ノード身元バインド、`stream` 専用線モードでクロスノードリプレイ攻撃を防御) |
| `skip-cert-verify`| Boolean| いいえ | `false` | TLS 証明書の検証をスキップするかどうか (本番環境では `false` を推奨) |
| `pool-size` | Integer | いいえ | `4` | TCP コネクションプールのサイズ (`h2` モードのスループットおよびバースト耐性を最適化) |
| `udp` | Boolean | いいえ | `true` | UDP パケット転送を有効にするかどうか |
| `interface-name` | String | いいえ | - | アウトバウンドにバインドする NIC 名 (マルチインターフェース・ポリシールーティングに対応) |
| `routing-mark` | Integer | いいえ | `0` | Linux アウトバウンドトラフィックの `fwmark` ルーティングマーク |
| `ip-version` | String | いいえ | `dual` | 名前解決と接続の優先度: `ipv4-prefer`、`ipv6-prefer`、`ipv4-only`、`ipv6-only` |

---

### 2.2 5種類のモード別ノード設定例

#### ① モード 1: `h2` (TLS 1.3 + HTTP/2 ストリーム多重化 - デフォルト推奨)
```yaml
- name: "Chitanda-H2-Tokyo"
  type: chitanda
  server: tokyo.yourdomain.com
  port: 443
  psk: "super-secret-pre-shared-key-32bytes-min"
  path: "/api/v1/sync"
  transport: "h2"
  sni: "tokyo.yourdomain.com"
  pool-size: 4
  udp: true
```

#### ② モード 2: `h3` (ネイティブ HTTP/3 & QUIC 0 隊頭閉塞)
```yaml
- name: "Chitanda-H3-Tokyo"
  type: chitanda
  server: tokyo.yourdomain.com
  port: 443
  psk: "super-secret-pre-shared-key-32bytes-min"
  path: "/api/v1/sync"
  transport: "h3"
  sni: "tokyo.yourdomain.com"
  udp: true
```

#### ③ モード 3: `auto` (動的プローブ・H2 $\leftrightarrow$ H3 自律切替)
```yaml
- name: "Chitanda-Auto-Tokyo"
  type: chitanda
  server: tokyo.yourdomain.com
  port: 443
  psk: "super-secret-pre-shared-key-32bytes-min"
  path: "/api/v1/sync"
  transport: "auto"
  sni: "tokyo.yourdomain.com"
  pool-size: 4
  udp: true
```

#### ④ モード 4: `stream` (RawStream 専用線・高速中継)
```yaml
- name: "Chitanda-Stream-Direct"
  type: chitanda
  server: 198.51.100.23
  port: 11323
  psk: "super-secret-pre-shared-key-32bytes-min"
  transport: "stream"
  server-id: "node-tokyo-01"
  udp: true
```

#### ⑤ モード 5: `h1` (純 IP / 証明書不要 / 全二重 HTTP/1.1 実験的チャネル)
```yaml
- name: "Chitanda-H1-DirectIP"
  type: chitanda
  server: 198.51.100.23
  port: 18200
  psk: "super-secret-pre-shared-key-32bytes-min"
  path: "/gateway/stream/v2"
  transport: "h1"
  udp: true
```

---

### 2.3 Mihomo 完全版クライアント設定ファイル例 (`config.yaml`)

```yaml
port: 7890
socks-port: 7891
allow-lan: false
mode: rule
log-level: info
ipv6: false

dns:
  enable: true
  listen: 0.0.0.0:1053
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - 223.5.5.5
    - 119.29.29.29
  fallback:
    - 8.8.8.8
    - 1.1.1.1

proxies:
  # 1. H2 メインラインノード
  - name: "Tokyo-H2"
    type: chitanda
    server: jp.example.com
    port: 443
    psk: "ch1tanda-auth-key-production-sample"
    path: "/api/v1/sync"
    transport: "h2"
    sni: "jp.example.com"
    pool-size: 4
    udp: true

  # 2. 原生 H3/QUIC ノード
  - name: "Tokyo-H3"
    type: chitanda
    server: jp.example.com
    port: 443
    psk: "ch1tanda-auth-key-production-sample"
    path: "/api/v1/sync"
    transport: "h3"
    sni: "jp.example.com"
    udp: true

  # 3. 智能自癒 Auto ノード
  - name: "Tokyo-Auto"
    type: chitanda
    server: jp.example.com
    port: 443
    psk: "ch1tanda-auth-key-production-sample"
    path: "/api/v1/sync"
    transport: "auto"
    sni: "jp.example.com"
    pool-size: 4
    udp: true

  # 4. 純 IP 免証明書 H1 ノード
  - name: "DirectIP-H1"
    type: chitanda
    server: 203.0.113.88
    port: 18200
    psk: "ch1tanda-auth-key-production-sample"
    path: "/gateway/stream/v2"
    transport: "h1"
    udp: true

  # 5. 専用線超高速 Stream ノード
  - name: "Tokyo-Stream"
    type: chitanda
    server: 203.0.113.88
    port: 11323
    psk: "ch1tanda-auth-key-production-sample"
    transport: "stream"
    server-id: "tokyo-node-01"
    udp: true

proxy-groups:
  - name: "PROXIES"
    type: select
    proxies:
      - "AUTO-FALLBACK"
      - "Tokyo-H2"
      - "Tokyo-Stream"
      - "Tokyo-H3"
      - "Tokyo-Auto"
      - "DirectIP-H1"
      - DIRECT

  - name: "AUTO-FALLBACK"
    type: fallback
    url: "http://www.gstatic.com/generate_204"
    interval: 300
    proxies:
      - "Tokyo-H2"
      - "Tokyo-Stream"
      - "Tokyo-H3"
      - "Tokyo-Auto"
      - "DirectIP-H1"

rules:
  - GEOIP,CN,DIRECT
  - MATCH,PROXIES
```

---

## 3. Xray-core サーバー・クライアント設定マニュアル

Xray-core において、`chitanda` は **Inbound (サーバーインバウンド)** としてトラフィックを受信・復号して Xray のルーティングディスパッチャーへ転送することも、**Outbound (クライアントアウトバウンド)** としてリモートの Chitanda ノードへ接続することも可能です。

### 3.1 Xray サーバーインバウンド設定パラメーター (`inbounds.settings`)

| フィールド | 型 | 必須 | デフォルト値 | 詳細説明 |
| :--- | :---: | :---: | :---: | :--- |
| `psk` | String | はい | - | 事前共有認証キー |
| `path` | String | いいえ | `/api/v1/sync` | プロトコル通信認証パス |
| `transport` | String | いいえ | `h2` | キャリアモード (`h2` / `h3` / `auto` / `stream` / `h1`) |
| `fallback` | String | いいえ | - | プローブ耐性フォールバック先 (例: `127.0.0.1:8080`、`unix:/run/nginx.sock`、外部 Web サイト等) |
| `strict_sni` | String | いいえ | - | 厳格な SNI 検証ドメイン (指定 SNI と一致しない場合は強制フォールバック) |
| `server_id` | String | いいえ | - | サーバーノード識別子 (`stream` モードでのクロスノードリプレイ攻撃防御) |
| `replay_file` | String | いいえ | - | 永続化リプレイ防止キャッシュのファイルパス (例: `/var/log/chitanda/replay.db`) |

---

### 3.2 Xray 5種類のモード別サーバーインバウンド設定例 (`inbounds`)

#### ① サーバー H2 メインラインインバウンド (TLS 1.3 および Web フォールバック対応)
```json
{
  "tag": "chitanda-inbound-h2",
  "port": 443,
  "protocol": "chitanda",
  "settings": {
    "psk": "super-secret-pre-shared-key-32bytes-min",
    "path": "/api/v1/sync",
    "transport": "h2",
    "strict_sni": "jp.example.com",
    "fallback": "127.0.0.1:8080"
  },
  "streamSettings": {
    "security": "tls",
    "tlsSettings": {
      "certificates": [
        {
          "certificateFile": "/etc/ssl/chitanda/fullchain.cer",
          "keyFile": "/etc/ssl/chitanda/private.key"
        }
      ],
      "alpn": ["h2", "http/1.1"]
    }
  }
}
```

#### ② サーバー H3 / QUIC ネイティブインバウンド
```json
{
  "tag": "chitanda-inbound-h3",
  "port": 443,
  "protocol": "chitanda",
  "settings": {
    "psk": "super-secret-pre-shared-key-32bytes-min",
    "path": "/api/v1/sync",
    "transport": "h3",
    "strict_sni": "jp.example.com",
    "fallback": "127.0.0.1:8080"
  },
  "streamSettings": {
    "security": "tls",
    "tlsSettings": {
      "certificates": [
        {
          "certificateFile": "/etc/ssl/chitanda/fullchain.cer",
          "keyFile": "/etc/ssl/chitanda/private.key"
        }
      ],
      "alpn": ["h3"]
    }
  }
}
```

#### ③ サーバー Auto (自動復帰・互換インバウンド)
```json
{
  "tag": "chitanda-inbound-auto",
  "port": 443,
  "protocol": "chitanda",
  "settings": {
    "psk": "super-secret-pre-shared-key-32bytes-min",
    "path": "/api/v1/sync",
    "transport": "auto",
    "strict_sni": "jp.example.com",
    "fallback": "127.0.0.1:8080"
  },
  "streamSettings": {
    "security": "tls",
    "tlsSettings": {
      "certificates": [
        {
          "certificateFile": "/etc/ssl/chitanda/fullchain.cer",
          "keyFile": "/etc/ssl/chitanda/private.key"
        }
      ],
      "alpn": ["h2", "h3", "http/1.1"]
    }
  }
}
```

#### ④ サーバー Stream (専用線 / 高スループット・プローブ無応答インバウンド)
```json
{
  "tag": "chitanda-inbound-stream",
  "port": 11323,
  "protocol": "chitanda",
  "settings": {
    "psk": "super-secret-pre-shared-key-32bytes-min",
    "transport": "stream",
    "server_id": "node-tokyo-01",
    "replay_file": "/var/log/chitanda/stream_replay.db"
  },
  "streamSettings": { "security": "none" }
}
```

#### ⑤ サーバー H1 (純 IP / 証明書不要 / 特徴排除インバウンド)
```json
{
  "tag": "chitanda-inbound-h1",
  "port": 18200,
  "protocol": "chitanda",
  "settings": {
    "psk": "super-secret-pre-shared-key-32bytes-min",
    "path": "/gateway/stream/v2",
    "transport": "h1",
    "fallback": "127.0.0.1:80"
  },
  "streamSettings": { "security": "none" }
}
```

---

### 3.3 Xray クライアントアウトバウンド設定パラメーター (`outbounds.settings`)

| フィールド | 型 | 必須 | デフォルト値 | 詳細説明 |
| :--- | :---: | :---: | :---: | :--- |
| `server` | String | はい | - | サーバーアドレスとポート (`ドメイン:ポート` または `IP:ポート`) |
| `psk` | String | はい | - | 事前共有認証キー (サーバー側と一致させる必要があります) |
| `server_name` | String | いいえ | (`server` と同一) | TLS SNI 検証ドメイン (TLS モード) |
| `path` | String | いいえ | `/api/v1/sync` | 偽装リクエストパス |
| `transport` | String | いいえ | `h2` | キャリアモード (`h2` / `h3` / `auto` / `stream` / `h1`) |
| `pool_size` | Integer | いいえ | `4` | TCP 物理コネクションプールサイズ (`h2` / `auto` モードで有効) |
| `server_id` | String | いいえ | - | サーバー識別子バインド (`stream` モード専用、クロスノードリプレイ防御) |
| `allow_insecure` | Boolean | いいえ | `false` | TLS 証明書検証をスキップするかどうか (デフォルト `false`、自己署名証明書テスト用) |

---

### 3.4 Xray 5種類のモード別クライアントアウトバウンド設定例 (`outbounds`)

```json
{
  "outbounds": [
    {
      "tag": "chitanda-out-h2",
      "protocol": "chitanda",
      "settings": {
        "server": "jp.example.com:443",
        "server_name": "jp.example.com",
        "psk": "super-secret-pre-shared-key-32bytes-min",
        "path": "/api/v1/sync",
        "transport": "h2",
        "pool_size": 4,
        "allow_insecure": false
      }
    },
    {
      "tag": "chitanda-out-h3",
      "protocol": "chitanda",
      "settings": {
        "server": "jp.example.com:443",
        "server_name": "jp.example.com",
        "psk": "super-secret-pre-shared-key-32bytes-min",
        "path": "/api/v1/sync",
        "transport": "h3",
        "allow_insecure": false
      }
    },
    {
      "tag": "chitanda-out-auto",
      "protocol": "chitanda",
      "settings": {
        "server": "jp.example.com:443",
        "server_name": "jp.example.com",
        "psk": "super-secret-pre-shared-key-32bytes-min",
        "path": "/api/v1/sync",
        "transport": "auto",
        "pool_size": 4,
        "allow_insecure": false
      }
    },
    {
      "tag": "chitanda-out-stream",
      "protocol": "chitanda",
      "settings": {
        "server": "203.0.113.88:11323",
        "psk": "super-secret-pre-shared-key-32bytes-min",
        "server_id": "node-tokyo-01",
        "transport": "stream"
      }
    },
    {
      "tag": "chitanda-out-h1",
      "protocol": "chitanda",
      "settings": {
        "server": "203.0.113.88:18200",
        "psk": "super-secret-pre-shared-key-32bytes-min",
        "path": "/gateway/stream/v2",
        "transport": "h1"
      }
    },
    {
      "tag": "direct",
      "protocol": "freedom"
    }
  ]
}
```

---

### 3.5 Xray 完全版サーバー本番設定ファイル例 (`server_production.json`)

```json
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "tag": "chitanda-in",
      "port": 443,
      "protocol": "chitanda",
      "settings": {
        "psk": "your-32-byte-secure-pre-shared-key-here",
        "path": "/api/v1/sync",
        "transport": "h2",
        "strict_sni": "status.chitanda.org",
        "fallback": "127.0.0.1:8080"
      },
      "streamSettings": {
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/ssl/chitanda.crt",
              "keyFile": "/etc/ssl/chitanda.key"
            }
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom"
    },
    {
      "tag": "blocked",
      "protocol": "blackhole"
    }
  ]
}
```

---

## 4. 3X-UI (Xray-UI) ノード運用とカーネルオンライン更新ガイド

3X-UI（および各種 Xray-UI 系列のパネル）は、Web 管理画面を通じて Xray 設定を視覚的に管理し、バックグラウンドの Xray プロセスを監視・常駐させるコントロールパネルです。3X-UI で配備されたノードは、基盤となる `/usr/local/x-ui/bin/xray-linux-*` バイナリ上で動作します。

### 4.1 3X-UI とクライアント双端のカーネル更新が必要な理由

高頻度なショートコネクションを多用するモバイルゲーム（例: 『ブルーアーカイブ』 / Blue Archive）や Web API ポーリングを行うアプリケーションにおいて、**接続のタイムアウト切断が発生したり、OpenClash ソフトウェアルーターやクライアントを長時間稼働させた後にポートの無応答（ハング）、Web 管理画面への接続不能、DNS タイムアウトが発生し、カーネルの再起動を余儀なくされる現象**が見られる場合、以下の要因が関係しています：

- **サーバー側の根本原因**: 旧版サーバーは宛先からのレスポンス完了・切断を受信した後、アップストリーム方向でクライアントからの明示的な FIN が届かないと 30 秒間のタイムアウトまでソケットを保持し続けます（H3 モードでは無期限に QUIC ストリームがハング）。ゲーム等の高頻度な通信が短時間に行われると、ソケットおよびファイルディスクリプタ（FD）が急速に枯渇します。
- **クライアント側の根本原因**: 双方向ハーフクローズ（Half-Close）時にインバンドマーカーが不足していると、サーバー側が既に切断されたことをクライアントの接続プールが迅速に検知できず、ローカルソケットが滞留。ソフトウェアルーターのファイルハンドルを占有し、`9090` などのコントロールポートや DNS 名前解決を阻害します。
- **協調的解決策**:
  1. **サーバー側**: 3X-UI の基盤カーネルを最新の `xray-chitanda` へ更新してください。サーバー側に **250ms グレースフル・ドレイン（Downstream-Triggered Drain）** 機構が導入されており、宛先のレスポンス完了時にクライアントへインバンド EOF を送信すると同時にドレインウィンドウを 250ms に制限。タイムアウト時は両端ソケットを強制クローズして即座にリソースを回収します。
  2. **クライアント側**: OpenClash / CMFA / PC 版コアを最新の `mihomo-chitanda` へ更新してください。インバンド EOF を正しく解釈し、ローカル接続プールを即時解放します。

---

### 4.2 3X-UI カーネル更新手順

#### 方法一: 3X-UI Web 管理画面でのオンライン切り替え・更新 (推奨)
1. ブラウザで 3X-UI 管理画面にログインします。
2. 左側メニューの **「Xray 設定」**（または **「パネル設定」**）を開きます。
3. **「バージョン切り替え / カーネルバージョン」** をクリックします。
4. バージョン一覧から最新の **`v26.3.27`**（または最新タグ）を選択します。
5. **更新を実行** すると、3X-UI が自動的に対応アーキテクチャのバイナリを取得し、バックグラウンドの Xray プロセスをホットリスタートします。

#### 方法二: 终端一键更新指令（不用进网页）
如果在终端操作，不能只执行 `rm`，而是需要一条龙“下载最新 Release $\rightarrow$ 解压覆盖 $\rightarrow$ 重启”：

```bash
curl -fsSL https://github.com/violetaini/chitanda/releases/download/v26.3.27/Xray-linux-64.zip -o /usr/local/x-ui/bin/Xray.zip && \
python3 -c "import zipfile, os; zipfile.ZipFile('/usr/local/x-ui/bin/Xray.zip').extract('xray', '/usr/local/x-ui/bin'); os.chmod('/usr/local/x-ui/bin/xray', 0o755); os.replace('/usr/local/x-ui/bin/xray', '/usr/local/x-ui/bin/xray-linux-amd64'); os.remove('/usr/local/x-ui/bin/Xray.zip')" && \
x-ui restart
```

> **注意**：`x-ui restart` 仅为重启面板服务，**不包含**缺失内核自动下载功能。若直接 `rm -f /usr/local/x-ui/bin/xray-linux-amd64` 后重启，面板会因为找不到二进制文件而提示 `未知版本 + error 运行状态`。请务必使用上述一键更新指令。

---

### 4.3 3X-UI 管理画面 5種類のモード別インバウンド設定ガイド

3X-UI の **「インバウンド一覧」 $\rightarrow$ 「インバウンドを追加」** における設定方法：

#### 1. `stream` モード (専用線 / 高スループット純 IP 直指定、証明書不要)
- **プロトコル**: `chitanda`
- **ポート**: 任意のポート (例: `11323`)
- **トランスポート (Transport)**: `stream`
- **事前共有鍵 (PSK)**: 高エントロピーな認証鍵 (例: `openssl rand -base64 32`)
- **Server ID**: ノード固有の識別子 (例: `node-tokyo-01`、クロスノードリプレイ攻撃防御用)
- **セキュリティ (Security)**: `none` (TLS 証明書不要、純 IP で通信可能)

#### 2. `h2` モード (本番パブリック環境推奨、高多重化・耐検閲)
- **プロトコル**: `chitanda`
- **ポート**: `443` または任意のポート
- **トランスポート (Transport)**: `h2`
- **事前共有鍵 (PSK)**: 任意の認証鍵
- **Path**: 偽装 API パス (例: `/api/v1/sync`)
- **セキュリティ (Security)**: `tls`
- **証明書パス**: 有効な SSL/TLS 証明書パス (`.cer` および `.key`)
- **Fallback (フォールバック)**: ローカルの Web ポート (例: `127.0.0.1:8080`) または外部サイト。未認証プローブは偽装サイトへ転送されます。

#### 3. `h3` モード (ネイティブ QUIC パケットロス耐性)
- **プロトコル**: `chitanda`
- **トランスポート (Transport)**: `h3`
- **セキュリティ (Security)**: `tls` (QUIC は TLS 証明書が必須)
- **ALPN**: `h3` を指定

#### 4. `auto` モード (インテリジェント自律フェイルオーバー)
- **プロトコル**: `chitanda`
- **トランスポート (Transport)**: `auto`
- **セキュリティ (Security)**: `tls`
- **ALPN**: `h2, h3, http/1.1`

#### 5. `h1` モード (純 IP / 証明書不要 / 特徴排除実験モード)
- **プロトコル**: `chitanda`
- **トランスポート (Transport)**: `h1`
- **Path**: `/gateway/stream/v2`
- **セキュリティ (Security)**: `none`

---

## 5. クライアント (OpenClash / Mihomo / CMFA) カーネルアップデートガイド

### 5.1 OpenClash ソフトウェアルーターのカーネルアップデート
1. OpenWrt 管理画面 $\to$ **OpenClash** プラグインを開きます。
2. **「プラグイン設定」 $\rightarrow$ 「バージョン更新」** を開きます。
3. **「Meta コアを更新」** をクリックします（Chitanda-OpenClash カスタム版では、Chitanda Releases から最新の `mihomo` コアが自動取得されます）。
4. *手動置換の場合*: 最新の `mihomo-linux-amd64`（またはルーターのアーキテクチャに適合するもの）をダウンロードし、ファイル名を `clash_meta` に変更した上で `/etc/openclash/core/clash_meta` に上書き配置し、`chmod +x /etc/openclash/core/clash_meta` を実行して OpenClash を再起動します。

### 5.2 Clash Meta For Android (CMFA) Android 端末のアップデート
1. [chitanda-cmfa Releases](https://github.com/violetaini/chitanda-cmfa/releases) へアクセスします。
2. 最新の APK パッケージをダウンロードし、端末へ上書きインストールします。

### 5.3 デスクトップクライアント (Mihomo Party / Clash Verge Rev 等)
1. Releases から `mihomo-windows-64.zip` / `mihomo-darwin-*.zip` を取得します。
2. 解凍した `mihomo` バイナリをクライアントの設定ディレクトリ内のコアバイナリと差し替え、クライアントを再起動します。

---

## 6. 高頻度ショートコネクションとモバイルゲーム向け最適化仕様 (Half-Close & ブルーアーカイブ事例)

### 6.1 ゲームおよび高頻度 API 通信のシーケンスモデル
『ブルーアーカイブ』（Blue Archive）を例にとると、端末（スマートフォン / エミュレーター）での UI タップ、ステージクリア決済、リソース読み込みなどにおいて、HTTP/1.1 による高頻度かつバースト的なショートリクエストが発生します：

```text
クライアント                                 Chitanda サーバー                              宛先ゲーム公式サーバー
    │                                               │                                               │
    ├─── 1. POST /game/api リクエスト送信 ─────────>├─── 2. 接続確立・リクエスト転送 ───────────────>│
    │                                               │                                               │
    │                                               │<── 3. 200 OK レスポンスデータ返送 ────────────┤
    │<── 4. レスポンスデータを転送 ─────────────────┤                                               │
    │                                               │<── 5. 通信終了、宛先が FIN/EOF を送信 ────────┤
    │                                               │    (宛先接続が切断され、downloadDone トリガー) │
    │                                               │                                               │
    │                                               │【旧実装の挙動】: サーバーが 30 秒間待機！      │
    │                                               │【発生する問題】: 毎分多数の接続が残留・スタック │
    │                                               │                  ルーターの FD 枯渇・ハング！  │
    │                                               │                                               │
    │                                               │【最新最適化】: 直ちに 250ms 高速回収フェーズへ │
    │<── 6. インバンド EOF [0x00,0x00] + FIN 送信 ──┤    (クライアントへ通知、250ms タイマー設定)   │
    │                                               │                                               │
    │├─── 7. クライアントが EOF 受信・ソケット回収 ─>│                                               │
    │                                               │─── 8. 250ms 経過時に両端ソケットを強制解放 ───┤
    ▼                                               ▼                                               ▼
    接続完全消滅 (ミリ秒単位で解放、ゲームの連打でも FD 残留ゼロ、ルーターの 9090 ポートや DNS が一切ハングしない！)
```

### 6.2 主要な最適化指標と実測検証
パブリックインターネット環境における負荷テスト（50 並行の連続バーストショートリクエスト）：
- **旧バージョンの挙動**: 接続が 30 秒間滞留し、システム内に `CLOSE_WAIT`/`FIN_WAIT` 状態のソケットが 50 以上残留。OpenClash の外部コントロールポートがタイムアウト。
- **最新バージョンの挙動**:
  - 単一リクエストのエンドツーエンドライフサイクルが 30 秒から **6〜15 ミリ秒** に短縮。
  - 50 並行の高頻度ショートコネクションが **325 ミリ秒** 以内にすべて完了し、優雅に解放。
  - `ss -tupan | grep 38300` の確認結果: **ソケット残留ゼロ、ファイルディスクリプタ（FD）リークゼロ**。

---

## 7. Mihomo / OpenClash 稼働堅牢性と Zero-DefaultResolver 規約

OpenClash ルーター環境および各種 Mihomo (Clash.Meta) クライアントでは、プロキシコアが Fake-IP や内蔵 DNS を迂回して実 IP を漏洩させる事故を防止するため、Mihomo コアのソースコード（`main.go`）に極めて厳格な防護的アサーションが組み込まれています：**プロキシのアウトバウンドアダプターが接続確立段階において Go 標準ライブラリのシステム DNS リゾルバ（`net.DefaultResolver`）を呼び出すことを一切禁止**。万一これに違反した場合、Mihomo は即座に stderr へ全 Goroutine スタックを出力し、`os.Exit(2)` でプロセスを強制終了します。

ルーターやモバイル端末が高頻度な UDP ゲームやドメイン指定ノードを利用する際の安定性を保証するため、Chitanda プロトコルは包括的な **Zero-DefaultResolver 規約** を実装しています：

### 7.1 コア防護メカニズム

1. **インメモリ IP パーサー (`parseUDPAddr`)**:
   - パケット受信およびターゲット逆引き処理において、Go 標準の `netip.ParseAddrPort` および `net.ParseIP` を使用した完全ロックフリー・ゼロアロケーションのメモリパースを採用。
   - OS や Go ランタイムの DNS 解決処理を一切呼び出さず、DNS ブロッキングオーバーヘッドも皆無です。
2. **Mihomo 専用ドメインリゾルバのシームレス連携 (`resolveUDPAddr`)**:
   - ノードがドメイン名（例: 中継ノード `iepl-tokyo.example.com`）として指定されている場合、Chitanda アウトバウンドアダプターはコールバック関数を通じて名前解決を Mihomo の `resolver.ProxyServerHostResolver` に完全委譲します。
   - 解決結果は Mihomo の DNS 優先ポリシー（`ipv4-prefer` / `ipv6-prefer` 等）に厳格に従い、OpenClash の Fake-IP キャッシュと完全に協調動作します。
3. **ルーターのポリシールーティングと `fwmark` バインド**:
   - OpenWrt の透過プロキシモードでは、カーネルが `fwmark` マーキングに基づいてアウトバウンドトラフィックを識別します。Chitanda は UDP リスニングソケット初期化時に、Mihomo の `c.dialer.ListenPacket` へ解決済みの実サーバー宛先 IP (`AddrPort`) を明示的に渡します。
   - これにより、宛先ソケットが不明な場合にデフォルトゲートウェイへ誤ってルーティングされデータが消失（ブラックホール化）する問題を根本から解決します。
4. **汎用 PacketConn インターフェースによる疎結合**:
   - 旧版の `*net.UDPConn` 具象型に対するハードな型アサーションを撤廃し、汎用的な `net.PacketConn` インターフェースへ抽象化。
   - OpenClash や Mihomo のデコレーター層接続（トラフィック統計、自己切断ガード、ポリシーバインドが付与されたラッパーオブジェクト）との完全な互換性を確保しています。

---

## 8. 長時間ストリーミング・LLM 推論対応と双方向アクティビティ自律更新アイドルタイムアウト (Shadowsocks-Style Activity Idle Timeout)

### 8.1 課題と背景 (LLM 推論・ストリーミング切断問題)
ChatGPT、Codex（Copilot）、Claude などの大規模言語モデル（LLM）では、数 MB に及ぶ巨大なコンテキスト・プロンプトを一括送信した後、推論エンジンが思考およびトークンの逐次生成（SSE / Server-Sent Events）を開始します。この際：
1. クライアントからのリクエストボディ送信は数秒以内で完了（`uploadDone` 発生）；
2. その後、宛先サーバーは 1〜3 分以上にわたり継続的に推論トークンを下りストリームとして返送；
3. **旧実装の欠陥**: クライアント送信完了から一律 60 秒経過で強制切断（`select { case <-time.After(60 * time.Second): cancel() }`）するロジックが存在したため、推論完了前に `stream disconnected before completion` エラーが発生して切断される問題がありました。

### 8.2 Shadowsocks スタイル双方向自律更新アーキテクチャ
標準的な Shadowsocks / Sing-box / V2Ray の長寿命中継モデルに準拠し、Chitanda は双方向アクティビティ監視機構（`activityReader`）を導入しました：

```text
    クライアント (Codex / ブラウザ)                Chitanda サーバー                         宛先 (OpenAI / Web)
          │                                           │                                           │
          ├─── 1. 巨大コンテキスト送信 (3MB) ─────────>├─── 2. リクエストボディ転送 ──────────────>│
          │    (約 2 秒で送信完了、uploadDone 記録)    │    (closeWriteConn でハーフクローズ送信)   │
          │                                           │                                           │
          │                                           │    ┌──────────────────────────────────┐   │
          │                                           │    │  双方向 activityReader 監視      │   │
          │                                           │    │  [DefaultIdleTimeout = 300s]     │   │
          │                                           │    └──────────────────────────────────┘   │
          │                                           │                                           │
          │                                           │<── 3. 推論開始・SSE トークン逐次返送 ─────┤
          │<── 4. SSE データをリアルタイム中継 ───────┤    ★ 1 バイト受信ごとにタイマーを 300s に │
          │    (思考時間 90 秒経過でも切断なし！)      │       即座に自動リセット！               │
          │                                           │                                           │
          │                                           │<── 5. 推論完了、宛先が FIN/EOF を送信 ────┤
          │                                           │    (downloadDone 発生)                    │
          │                                           │─── 6. 250ms グレースフル排空タイマー ────>│
          ▼                                           ▼                                           ▼
          全トークン正常受信完了 (接続正常終了、FD 枯渇なし、60秒強制切断の根絶！)
```

### 8.3 5 大トランスポートモードへの完全適用
本仕様は Chitanda が提供する **5 種類すべての転送キャリア**（`stream`, `h2`, `h3`, `auto`, `h1`/`plain-h1`）に均一に適用されています：
- **`DefaultIdleTimeout = 300s`**: 双方向ともに完全な無通信（完全静默）状態が 5 分間継続した場合にのみ切断。
- **`DefaultDrainTimeout = 250ms`**: レスポンス完了後の余剰パケット排空猶予期間。
- **ゲーム通信との両立**: 宛先切断時の 250ms 高速回収と協調し、高頻度なゲーム API ポーリングでもソケットが滞留・蓄積しません。

---

## 9. 本番運用セキュリティとデプロイのベストプラクティス

1. **PSK 鍵の強度**:
   - 必ずランダムに生成された強度の高い認証鍵を使用してください（`openssl rand -base64 32` などによる 32 バイト以上の高エントロピー鍵を推奨）。
2. **プローブ耐性 Fallback 偽装**:
   - 本番環境では `fallback`（ローカルで稼働する Nginx/Caddy または実在の外部 Web サイト）を必ず設定してください。未認証のアクティブプローブに対して一般の Web サイトと全く同じ応答を返します。
3. **Strict SNI 保護**:
   - `strict_sni` を有効化することで、指定外のドメインや IP 直指定でのスキャンによる TLS 証明書の特徴抽出を防御できます。
