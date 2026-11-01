# shawk 次期設計案：PostgreSQL ＋ OpenTelemetry ＋ Grafana

状態：実装済み（2026-10-31、ブランチ `next-design`）。もとは SQLite 台帳の実装からの変更案として書いた。実装で決めた細部は §9、実装中に見つけた未決事項は §10 にある。英語の設計文書は `docs/design.md`。

この案に反映済みの判断：

| 判断 | 内容 | 反映先 |
|---|---|---|
| レビュー P0-1 | Prometheus のラベルから相手アドレスを外し、相手は `service.peer.name` に一本化する | §4.2, §4.3 |
| レビュー P0-2 | 使われなくなった系列を 15 分で送るのをやめ、相手数に上限を設ける | §3.5, §4.3 |
| レビュー P0-3 | 両端で記録した同じ依存の計上規約を決め、二重計上をなくす | §4.4, §5.3 |
| レビュー P0-4 | 観測区間を残し、「使われていない」と「観測していない」を区別する | §3.5, §4.5, §5.2 |
| レビュー P0-5 | Postgres のアラートを時系列形式で組み、空の結果を Normal にし、消滅は明示的な行で表す | §6.2 |
| 名前 | ローカルの `service.name` は、環境変数がなければ実行ファイル名にする（OBI と同じ） | §3.3 |
| 書き込み | PostgreSQL への書き込みと名前の付与を、エージェントから Collector の shawk connector に移す | §2, §4 |
| OBI | OBI はアプリ層の計装として並べて動かす。shawk のトレーサを OBI に寄与する計画はない | §7 |
| OBI との並走 | サービスを Prometheus の `job` で表して OBI とそろえ、OBI の設定・Collector・Grafana のつなぎ方を決める | §4.3, §5.1, §7.3, §7.4 |

レビュー P0 の根拠は[類似ツール比較と設計レビュー](../reports/shawk%20類似ツール比較と設計レビュー.md)、OBI の調査は `research_notes/OBI土台化の検討/` にある。

## 1. 目的と範囲

- 画面は Grafana（または同等のダッシュボード・アラートツール）だけにする。CLI の問い合わせコマンド（`who-uses`, `deps`, `can-i-remove`, `unused`, `diff`, `graph`, `status`）、エージェント間の HTTP API、各ホストの SQLite 台帳は廃止する。
- shawk が外に約束するもの（契約）は二つだけにする。
  - PostgreSQL の `shawk_v1` スキーマのビューと関数（§5）
  - Prometheus に届くメトリクスの名前とラベル（§4.3）
- エージェントが送る OTLP（§3）と shawk connector の設定（§4.6）は shawk の内部の取り決めで、両者は同じ版をそろえて配る。
- Grafana のダッシュボード、アラートルール、Prometheus の recording rule は、契約の使い方の見本として `packaging/grafana/` と `packaging/prometheus/` に同梱する。
- `shawk flows`（そのホストのフローをその場で見るデバッグ用の CLI）は残す。

## 2. 構成

```
 各ホスト
   eBPF ─ shawk agent ── OTLP（エッジの詳細）──→ [shawk Collector] otlp/shawk ─→ shawk connector
   OBI（アプリ層） ───── OTLP ─────────────────→ [shawk Collector] otlp ─→ OBI 用のパイプライン

 shawk connector ─┬─→ PostgreSQL（関係・観測区間）
                  └─→ 集約した数値 ─→ Prometheus 互換ストア
 OBI 用のパイプライン ─→ トレース・メトリクスの送り先

 PostgreSQL ＋ Prometheus ＋ OBI の送り先 ─→ Grafana
```

- **shawk agent**：eBPF による収集は現行のまま（TCP は `inet_sock_set_state` とソケットイテレータ、UDP は fentry、カーネル内で依存単位に束ね、15 秒ごとに回収する）。結果をエッジの詳細（アドレス、プロセスの属性）つきの OTLP で送るだけで、DB には触れない。
- **shawk connector**：Collector の部品（connector）として実装し、標準の部品と組み合わせた独自ビルドの Collector で動かす。OBI の receiver は組み込まない。三つの仕事を受け持つ（§4）。
  - PostgreSQL への関係と観測区間の書き込み
  - 相手の名前（`service.peer.name`）の付与
  - アドレスを落として集約した数値の Prometheus への転送
- **OBI**：別プロセスとして各ホストで動かし、HTTP・gRPC・DB などアプリ層のメトリクスとトレースを担う。OTLP の送り先は同じ Collector の別の受け口にする（§7）。
- 「依存が存在するか」は PostgreSQL を正、「どれだけ流れたか」は Prometheus を正とする。両者は名前（`service.name`, `service.peer.name`, `server.port`, `network.transport`, `host.id`）でつなぎ、DB をまたいだ結合はしない。

## 3. エージェントが送るもの

### 3.1 エッジのメトリクス

エッジ（依存）ごとに、次のメトリクスを 15 秒ごとに送る。

| OTel の名前 | 種類・単位 | 内容 | Prometheus へ |
|---|---|---|---|
| `shawk.connection.opened` | Counter, `{connection}` | 確立した接続 | 集約して転送 |
| `shawk.connection.failed` | Counter, `{connection}` | 接続の失敗（クライアント側だけで観測できる） | 集約して転送 |
| `shawk.connection.count` | UpDownCounter, `{connection}` | 区間の終わりに開いていた接続 | 集約して転送 |
| `shawk.network.io` | Counter, `By` | 送受信バイト。`network.io.direction` = `transmit` / `receive` | 集約して転送 |
| `shawk.udp.datagrams` | Counter, `{datagram}` | UDP の送受信数。`network.io.direction` つき | 集約して転送 |
| `shawk.tcp.retransmits` | Counter, `{segment}` | 自分の送信の再送 | 集約して転送 |
| `shawk.tcp.rtt` | Histogram（境界なし）, `s` | 平滑化 RTT の標本 | 集約して転送 |
| `shawk.edge.first_seen` | Gauge, `s` | このエッジを初めて見た時刻（Unix 秒） | 転送しない |
| `shawk.edge.last_seen` | Gauge, `s` | このエッジを最後に見た時刻（Unix 秒） | 転送しない |

- カウンタは累積（cumulative）で送る。送信が一時的に失敗しても、次に成功した送信で合計が追いつく。
- RTT は境界なしの Histogram にすることで、和と回数だけで平均が求まる。
- `first_seen` と `last_seen` は、エッジが活動した（接続、バイト、開いている接続のいずれかがあった）時刻で進める。送り続けているだけの時刻では進めない。

### 3.2 属性

resource 属性（送信ごとに一つ）：

| 属性 | 値 |
|---|---|
| `host.id` | `/etc/machine-id`、なければ `/var/lib/dbus/machine-id`（OBI と同じ取り方） |
| `host.name` | ホスト名 |
| `host.ip` | ホストのアドレスの一覧（コンテナの名前空間のものを含む） |
| `os.version` | カーネルのバージョン |
| `service.name` / `service.version` | `shawk-agent` / エージェントの版 |

エッジのデータ点の属性：

| 属性 | 値 |
|---|---|
| `service.name` | ローカルのプロセスのサービス名（§3.3） |
| `process.executable.name` / `process.executable.path` | 実行ファイル名とパス |
| `process.command` | comm |
| `shawk.unit` | cgroup から求めた systemd ユニット名など（一時的な名前は現行どおり正規化する） |
| `shawk.role` | `client`（自分が接続した）/ `server`（自分が受け付けた） |
| `network.transport` | `tcp` / `udp` |
| `network.local.address` / `network.peer.address` | ローカルと相手のアドレス |
| `server.port` | サービスポート（役割にかかわらず常にサーバ側のポート） |
| `shawk.netns` | ネットワーク名前空間の inode |

- `network.io.direction` は送受信の向きにだけ使い、クライアントかサーバかの役割は `shawk.role` で表す（semconv の定義に従う）。
- PID は属性にしない。プロセスが起動し直すたびに系列が変わってしまうため。

### 3.3 ローカルのサービス名

`service.name` は次の順で最初に得られたものを使う。既定は OBI と同じ順序にしてある。

1. プロセスの環境変数の `OTEL_SERVICE_NAME`、なければ `OTEL_RESOURCE_ATTRIBUTES` の `service.name`（`/proc/PID/environ` から `OTEL_` で始まる変数だけを読み、他は捨てる）
2. 実行ファイル名（`/proc/PID/exe` の basename。読めなければ comm）

`-service-name-fallback=unit` を指定すると、2 の代わりに systemd ユニット名を使う。

注意点：

- 同じホストで同じ実行ファイル（`ruby`、`python`、`java`、`php-fpm` など）を使う別々のサービスは、環境変数で名前を与えない限り、Prometheus の数値では同じ `job` に混ざる。PostgreSQL では `shawk.unit` で区別できる。
- OBI は Java について Spring Boot の名前や JAR 名を使うが、shawk は実行ファイル名（`java`）になる。
- 上の二つに当たるサービスには `OTEL_SERVICE_NAME` を設定することを勧める。systemd のドロップインの `Environment=` で足り、OBI とも名前が一致する。

### 3.4 待ち受けポートとエージェント自身

待ち受けポートは、ポートごとに `shawk.listener.first_seen` と `shawk.listener.last_seen`（Gauge, Unix 秒）を送る。属性は `network.transport`、`network.local.address`、`server.port`、`shawk.netns` と、プロセスの属性（§3.2）。Prometheus には転送しない。

エージェント自身のメトリクス：

| OTel の名前 | 内容 | Prometheus へ |
|---|---|---|
| `shawk.agent.up` | 動いている間 1 を送り続ける。属性 `shawk.netns.scope`（`all` または inode） | 転送 |
| `shawk.agent.segment.start` | 現在の観測区間の始まり（Unix 秒。§3.5） | 転送しない |
| `shawk.agent.udp.traced` | UDP を追跡できているか（0/1） | 転送 |
| `shawk.agent.flows.dropped` | フロー表があふれて捨てた更新（Counter） | 転送 |
| `shawk.agent.export.failures` | OTLP の送信の失敗（Counter） | 転送 |

### 3.5 送り方の規則

- **一回の送信で一区間**：エージェントは 15 秒ごとに、その時点で生きている系列すべてを一つの OTLP リクエストで送る。
- **アイドル系列の破棄**：最後の活動から 15 分（`-idle-ttl`）たったエッジと待ち受けポートは、送るのをやめて状態も捨てる（P0-2）。再び現れたらカウンタは 0 から始まる。
- **観測区間**（P0-4）：
  - エージェントが起動したとき、`shawk.agent.segment.start` を起動時刻にする。
  - OTLP の送信の失敗が「アイドル TTL − 1 分」より長く続いた場合は、送信が戻った時点で `shawk.agent.segment.start` を「今 − アイドル TTL」に進める。その間に活動を終えて捨てたエッジは届いていないかもしれないが、TTL 内のエッジはまだ送り続けているので、そこから先の観測は欠けていない。

## 4. shawk connector

### 4.1 役割

`otlp/shawk` 受け口に届いたエージェントの OTLP を処理する。リクエストごと、ホストごと（resource ごと）に次を行う。

1. エッジ・待ち受けポート・プロセス・アドレスの変化を、ホスト単位で手元に溜める。
2. 1 分ごと（`write_interval`）に、ホストごとの変化と観測区間を一つのトランザクションで PostgreSQL に書く（§4.5）。
3. エッジのメトリクスに相手の名前を付け（§4.2）、アドレスを落として集約し（§4.3）、後段のパイプラインへ渡す。

PostgreSQL の書き込み権限を持つのは connector だけで、エージェントは DB の資格情報を持たない。

### 4.2 相手の名前

connector は PostgreSQL の `shawk_v1.service_endpoints`、`shawk_v1.client_endpoints`、`shawk_v1.agent_addrs` を手元に保持する。1 分ごとに読み直し、自分が書いた変化もその場で反映する。`service.peer.name` は次のように決める。

| 役割 | 相手 | `service.peer.name` |
|---|---|---|
| client | 相手のアドレスとポートで待ち受けているサービスが `service_endpoints` で分かる | そのサービス名 |
| server | 同じアドレスの組とポートのクライアント側のエッジが `client_endpoints` で分かる | クライアントのサービス名 |
| 両方 | 分からないが、設定した名前付き CIDR に入る | その名前（例 `office-lan`） |
| 両方 | 分からず、プライベート範囲 | `~unresolved` |
| 両方 | 分からず、それ以外 | `~external` |

これとは別に、相手のアドレスがエージェントの生きているホストのもの（`agent_addrs`。ループバックを含む）かどうかを `shawk.peer.agent`（true / false）で付ける。true なら相手側の系列もあるので、§4.4 の規約はこれを使って二重計上を避ける。

（改訂：当初はサーバ側でエージェントのいるクライアントを `~agent` という名前に畳んでいたが、再送の `src` が分からなくなるため、名前と「相手にエージェントがあるか」を分けた。§10 の未決事項を参照。）

- 区分の値は `~` で始める。実在のサービス名と衝突させないため。
- 名前付き CIDR は connector の設定 `peer_cidrs` で与える。最も狭い範囲が勝つ。
- 名前は「集約した時点の最善の推定」であり、帰属の正は PostgreSQL だと文書に明記する。
- 新しいサーバの待ち受けポートが PostgreSQL に入るまで（最大 1 分）は、クライアント側が `~unresolved` で出て、その後サービス名に切り替わることがある。

### 4.3 Prometheus に届くメトリクス

connector は §3.1 の「集約して転送」のメトリクスを、次の属性だけに減らして合算する。エージェント自身のメトリクスはそのまま転送する。

出力は **(ホスト, ローカルのサービス) ごとに一つの resource** にまとめ、その `service.name` をローカルのサービス名にする。Prometheus は resource の `service.name` を `job` ラベルにするので、shawk の数値と OBI の数値が同じサービスについて同じ `job` を持つ（OBI も計装したサービスを resource の `service.name` にしている）。

| 属性 | Prometheus 上のラベル |
|---|---|
| resource の `service.name`（ローカルのサービス）と `service.namespace`（あれば） | `job`（namespace があれば `namespace/name`） |
| resource の `service.instance.id`（= `host.name`） | `instance` |
| resource の `host.id` / `host.name` | `host_id` / `host_name`（Prometheus の `promote_resource_attributes` で昇格させる） |
| `service.peer.name` | `service_peer_name` |
| `shawk.peer.agent` | `shawk_peer_agent`（`true` / `false`） |
| `shawk.role` | `shawk_role` |
| `server.port` | `server_port` |
| `network.transport` | `network_transport` |
| `network.io.direction`（バイトと UDP のみ） | `network_io_direction` |

エージェント自身のメトリクスは resource の `service.name` が `shawk-agent` なので、`job="shawk-agent"` になる。

`service.namespace` は、エージェントがプロセスの `OTEL_RESOURCE_ATTRIBUTES` から読めたときだけ付ける。

Prometheus 上の名前は `shawk_connection_opened_total`、`shawk_connection_failed_total`、`shawk_connection_count`、`shawk_network_io_bytes_total`、`shawk_udp_datagrams_total`、`shawk_tcp_retransmits_total`、`shawk_tcp_rtt_seconds_sum` / `_count`、`shawk_agent_*` になる。

系列数の上限（P0-1, P0-2）：

- 相手アドレス、ローカルアドレス、名前空間、プロセスの詳細は Prometheus に送らない。正確な値は PostgreSQL にある。どうしても必要な場合だけ、connector の `keep_peer_address: true` で `network.peer.address` を残せる。
- `(host, service.name, shawk.role)` ごとに `service.peer.name` は最大 50 種類（`max_peers`）とし、超えた分は `~other` に畳む。
- 入力がなくなってから 15 分たった出力の系列は捨てる。
- エッジ系列の数は「ホスト × ローカルのサービス × 相手のサービス（または区分）× ポート × 役割」で決まり、相手のレプリカ数や IP の入れ替わりでは増えない。

累積カウンタの合算：

- 複数の入力系列（相手のアドレス違い）を一つの出力系列にまとめるので、単純な和では入力が消えたときに値が減り、Prometheus がリセットと誤解する。
- connector は入力系列ごとに前回の値を覚えて差分をとり（値が減ったらリセットとみなす）、出力系列の累積値に足す。入力系列が消えても出力は減らない。
- この状態を持つため、同じホストのデータは同じ connector に届く必要がある。connector を複数台にするときは、前段の Collector に loadbalancing exporter を置き、resource で振り分ける。connector が再起動すると出力系列は 0 から始まり直すが、Prometheus はこれを通常のリセットとして扱う。

Prometheus 側の設定：`--web.enable-otlp-receiver`、`promote_resource_attributes: [host.id, host.name]`、`out_of_order_time_window: 30m`。カウンタは累積のまま送る（Prometheus の delta 対応は実験段階）。

### 4.4 二重計上の規約

両端にエージェントがあると、同じ依存がクライアント側（`shawk_role="client"`）とサーバ側（`shawk_role="server"`）の両方に出る。規約は次のとおり（P0-3）。

| メトリクス | 依存単位の値の取り方 |
|---|---|
| 接続数、開いている接続、バイト数、UDP 数、RTT | クライアント側を正とする。サーバ側は相手にエージェントがない場合（`shawk_peer_agent="false"`）だけ使う |
| 接続の失敗 | クライアント側だけ（サーバには届かないため） |
| 再送 | 両側を使う。各ソケットが自分の送信を再送した数なので重複ではない。`shawk_role` で送信側を区別する。サーバ側の系列もクライアントのサービス名を持つので、`src` が分かる |

サーバ側の `shawk_peer_agent="true"` の系列とクライアント側の系列は重ならないように作ってあるので、依存単位の値は和集合をとるだけで求まる。依存単位の系列は recording rule で作り、ダッシュボードとアラートはこれを使う。

```yaml
groups:
  - name: shawk-dependencies
    rules:
      - record: shawk:dependency_connections:rate5m
        expr: |
          sum by (src, dst, server_port, network_transport) (
              label_replace(label_replace(
                rate(shawk_connection_opened_total{shawk_role="client"}[5m]),
                "src", "$1", "job", "(.*)"), "dst", "$1", "service_peer_name", "(.*)")
            or
              label_replace(label_replace(
                rate(shawk_connection_opened_total{shawk_role="server", shawk_peer_agent="false"}[5m]),
                "dst", "$1", "job", "(.*)"), "src", "$1", "service_peer_name", "(.*)")
          )
      - record: shawk:dependency_connection_failures:rate5m
        expr: |
          sum by (src, dst, server_port, network_transport) (
            label_replace(label_replace(
              rate(shawk_connection_failed_total{shawk_role="client"}[5m]),
              "src", "$1", "job", "(.*)"), "dst", "$1", "service_peer_name", "(.*)"))
      # バイト数・RTT の和と回数も接続数と同じ形で作る
```

`or` の両辺は `shawk_role` が違うので、同じラベル集合になることはなく、実質的に和集合になる。

### 4.5 PostgreSQL への書き込み

- エッジ・待ち受けポート・プロセス・アドレスは、`first_seen = least(...)`、`last_seen = greatest(...)` で upsert する。順序の入れ替わりや再送があっても結果は同じになるので、connector を複数台にしても書き込みは衝突しない。
- `last_seen` だけが進んだエッジは、`write_interval` ごとにまとめて一回だけ書く。
- 観測区間（P0-4）は、同じトランザクションで `agent_sessions` に書く。
  - キーは `(host_id, started_at = shawk.agent.segment.start)`。
  - `last_heartbeat` は、そのトランザクションに含めた最新のデータ点の時刻にする。つまり「この時刻までの観測は DB に反映済み」を意味する。
  - `udp_traced`、`netns_scope`、`dropped_flows` もエージェントのメトリクスから書く。
- 観測の空白は次のときに残る。
  - エージェントが止まっていた、または再起動した（区間の始まりが変わる）。
  - 送信の失敗が TTL を超えて続いた（§3.5）。
- connector が書き込む前に落ちた場合、失うのは最大 `write_interval` 分の変化である。その間のエッジはエージェントが TTL の間送り続けるので、再起動後に届き直す。
- DB が止まっている間、connector は変化を手元に溜め続け、復旧後にまとめて書く。溜まる量は時間ではなくエッジの数に比例する。

### 4.6 Collector の設定例

実装の設定例は `packaging/collector/config.yaml` にある。ここはその要約で、二回の敵対的レビュー（§11, §12）で変わった点を反映している。

```yaml
receivers:
  otlp/shawk:                 # shawk agent 専用の受け口。TLS とクライアント証明書を必須にする
    protocols:
      grpc:
        endpoint: 0.0.0.0:4327
        max_recv_msg_size_mib: 16
        tls: &shawk_tls
          cert_file: /etc/shawk/tls/collector.crt
          key_file: /etc/shawk/tls/collector.key
          client_ca_file: /etc/shawk/tls/agents-ca.crt
      http:
        endpoint: 0.0.0.0:4328
        max_request_body_size: 16777216
        tls: *shawk_tls
  otlp:                       # OBI など。こちらもクライアント証明書を必須にする
    protocols:
      grpc: { endpoint: 0.0.0.0:4317, tls: *shawk_tls }
      http: { endpoint: 0.0.0.0:4318, tls: *shawk_tls }

connectors:
  shawk:
    postgres:
      dsn_file: /etc/shawk/postgres-dsn
      migrate: false            # スキーマは shawk-migrate で当てる
    write_interval: 1m          # 1 分以下
    idle_ttl: 15m
    max_peers: 50
    peer_cidrs:
      office-lan: 192.168.10.0/24
    retention: 26280h           # 3 年。0 なら消さない

processors:
  memory_limiter: { check_interval: 1s, limit_percentage: 80, spike_limit_percentage: 20 }
  batch: {}

exporters:
  otlp_http/prometheus:
    endpoint: http://prometheus:9090/api/v1/otlp
  otlp_grpc/traces:           # Tempo などトレースの送り先
    endpoint: tempo:4317

service:
  pipelines:
    metrics/shawk-in:         # connector の前に batch を置かない（一回の送信を一区間として扱うため）
      receivers: [otlp/shawk]
      processors: [memory_limiter]
      exporters: [shawk]
    metrics/shawk-out:        # 出力は connector の時計の時刻なので batch してよい
      receivers: [shawk]
      processors: [batch]
      exporters: [otlp_http/prometheus]
    metrics/obi:              # batch しない（ホストの時計の時刻のまま。§12）
      receivers: [otlp]
      processors: [memory_limiter]
      exporters: [otlp_http/prometheus]
    traces/obi:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [otlp_grpc/traces]
```

## 5. PostgreSQL の契約

### 5.1 テーブル（内部。`shawk` スキーマ）

PostgreSQL 14 以上を前提とする（多重範囲型 `tstzmultirange` と再帰問い合わせの `CYCLE` 句を使う）。

```sql
CREATE TABLE shawk.hosts (
  id            text PRIMARY KEY,          -- machine-id とホスト名のハッシュ（現行の hostID と同じ）
  machine_id    text NOT NULL,             -- resource の host.id。OBI のデータとの突き合わせに使う
  hostname      text NOT NULL,
  kernel        text NOT NULL,
  agent_version text NOT NULL,
  first_seen    timestamptz NOT NULL,
  last_seen     timestamptz NOT NULL
);

-- エージェントが観測できていた区間（P0-4）
CREATE TABLE shawk.agent_sessions (
  host_id        text NOT NULL REFERENCES shawk.hosts,
  started_at     timestamptz NOT NULL,     -- 観測区間の始まり（shawk.agent.segment.start）
  last_heartbeat timestamptz NOT NULL,     -- この時刻までの観測は DB に反映済み
  udp_traced     boolean NOT NULL,
  netns_scope    text NOT NULL,            -- 'all' または追跡している netns の inode
  dropped_flows  bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (host_id, started_at)
);

CREATE TABLE shawk.host_addrs (    -- §12 で、アドレスを持っていた期間ごとの行にした
  host_id    text NOT NULL REFERENCES shawk.hosts,
  addr       inet NOT NULL,
  first_seen timestamptz NOT NULL,
  last_seen  timestamptz NOT NULL,
  PRIMARY KEY (host_id, addr)        -- 0009 で (host_id, addr, first_seen)
);

CREATE TABLE shawk.processes (
  id           bigserial PRIMARY KEY,
  host_id      text NOT NULL REFERENCES shawk.hosts,
  unit         text NOT NULL,
  comm         text NOT NULL,
  exe          text NOT NULL DEFAULT '',
  service_name text NOT NULL,               -- §3.3 の規則で決めた名前
  first_seen   timestamptz NOT NULL,
  last_seen    timestamptz NOT NULL,
  UNIQUE (host_id, unit, comm)
);

CREATE TABLE shawk.edges (
  id          bigserial PRIMARY KEY,
  host_id     text NOT NULL REFERENCES shawk.hosts,
  process_id  bigint NOT NULL REFERENCES shawk.processes,
  role        text NOT NULL CHECK (role IN ('client', 'server')),
  proto       text NOT NULL CHECK (proto IN ('tcp', 'udp')),
  local_addr  inet NOT NULL,
  remote_addr inet NOT NULL,
  port        integer NOT NULL,             -- サービスポート
  netns       bigint NOT NULL,
  first_seen  timestamptz NOT NULL,
  last_seen   timestamptz NOT NULL,
  UNIQUE (host_id, role, proto, local_addr, remote_addr, port, netns, process_id)
);

CREATE TABLE shawk.listeners (
  host_id    text NOT NULL REFERENCES shawk.hosts,
  process_id bigint REFERENCES shawk.processes,
  proto      text NOT NULL,
  addr       inet NOT NULL,
  port       integer NOT NULL,
  netns      bigint NOT NULL,
  first_seen timestamptz NOT NULL,
  last_seen  timestamptz NOT NULL,
  PRIMARY KEY (host_id, proto, addr, port, netns)
);
```

### 5.2 観測区間（P0-4）

```sql
-- [since, until] のうち、ホストが観測できていなかった区間
CREATE FUNCTION shawk_v1.unobserved(since timestamptz, until timestamptz,
                                    tolerance interval DEFAULT '3 minutes')
RETURNS TABLE (host text, gap_start timestamptz, gap_end timestamptz)
LANGUAGE sql STABLE AS $$
  SELECT h.hostname, lower(g), upper(g)
  FROM shawk.hosts h
  CROSS JOIN LATERAL unnest(
    tstzmultirange(tstzrange(since, until))
    - coalesce((SELECT range_agg(tstzrange(s.started_at, s.last_heartbeat + tolerance))
                FROM shawk.agent_sessions s WHERE s.host_id = h.id),
               '{}'::tstzmultirange)
  ) AS g
  WHERE h.last_seen >= since;
$$;
```

- `tolerance` は connector の `write_interval` の 2〜3 倍にする。
- Grafana では、この関数を注釈（`time` と `timeend`）として全パネルに重ねると、観測の空白が網掛けで見える。

### 5.3 契約のビュー（`shawk_v1` スキーマ）

| ビュー | 主な列 | 用途 |
|---|---|---|
| `dependencies` | `client_host`, `client_service`, `client_unit`, `server_host`, `server_service`, `server_addr`, `port`, `proto`, `first_seen`, `last_seen`, `observed_by`, `client_observed_until`, `server_observed_until` | 論理的な依存 1 件を 1 行にしたもの |
| `graph_nodes` / `graph_edges` | Node Graph が要求する列（`id`, `title`, `subtitle`, `mainstat` / `id`, `source`, `target`, `mainstat`） | 依存マップ |
| `dependency_changes` | `time`, `change`（appeared / disappeared）, `client_service`, `server_service`, `port` | 変化の表と注釈 |
| `service_endpoints` | `addr`, `port`, `proto`, `host`, `service` | connector が `service.peer.name` を決める |
| `client_endpoints` | `client_addr`, `server_addr`, `port`, `proto`, `host`, `service` | connector がサーバ側の相手（クライアント）の名前を決める |
| `agent_addrs` | `addr`, `host` | connector が `shawk.peer.agent` を判定する |
| `agents` | `host`, `started_at`, `last_heartbeat`, `udp_traced`, `netns_scope`, `dropped_flows`, `alive` | エージェントの状態 |

`dependencies` の組み立て（P0-3）：

- クライアント側の `edges`（`role='client'`）とサーバ側の `edges`（`role='server'`）を、アドレスの組（`client.local_addr = server.remote_addr`, `client.remote_addr = server.local_addr`）とポートで突き合わせ、1 件にまとめる。
- `observed_by` は、両側で見えていれば `both`、片側だけなら `client` か `server`。片側だけの依存は、相手にエージェントがないか、間に NAT やロードバランサがあることを示す。
- `first_seen` は両側の小さい方、`last_seen` は大きい方。
- `client_observed_until` と `server_observed_until` は、それぞれのホストの最新の `last_heartbeat`（P0-4）。`last_seen` が古くても `client_observed_until` が新しければ「本当に使われていない」。両者が近ければ「エージェントが止まって見えなくなった」可能性がある。

### 5.4 権限

- connector：`shawk` スキーマへの書き込みと `shawk_v1` の読み取りだけを持つロール。資格情報は Collector のホストにだけ置く。
- Grafana：`shawk_v1` の SELECT 権限だけを持つロール。`statement_timeout` と `default_transaction_read_only` を設定する。

## 6. Grafana

### 6.1 ダッシュボード

| ダッシュボード | 主なデータ源 |
|---|---|
| フリート概要（エージェントの稼働、観測の空白、ドロップ、UDP 未追跡、今日増えた依存） | Postgres（`agents`, `unobserved()`）、Prometheus（`shawk_agent_*`） |
| 依存マップ（対象と深さを変数で選ぶ。再帰 SQL は（サービス, 深さ）の `UNION` で辿り、深さの上限を入れる。§12） | Postgres（`graph_nodes_between`, `graph_edges_between`） |
| 依存の詳細（接続数、失敗率、再送、RTT と、両端・初めて見た時刻・最後に見た時刻・観測区間） | Prometheus（recording rule）、Postgres（`dependencies`） |
| 変化（現れた依存・消えた依存を表と注釈で） | Postgres（`dependency_changes`） |
| アプリ層（HTTP・gRPC・DB の RED とトレース）。実装したのは HTTP の RED と shawk の依存だけで、gRPC・DB の RED とトレースは §8 に回した | OBI のメトリクスとトレース |

### 6.2 アラート（P0-5）

Grafana の PostgreSQL データソースは、アラートの条件に**時系列形式**のクエリしか使えないと文書化されている（表形式でも動くとする文書もあり、食い違っている。対象の Grafana で確かめるまでは時系列形式で組む）。そのため、SQL のアラートは次の形にそろえる。

- `time` 列、ラベルにする文字列の列、数値の `value` 列を 1 つ返す。数値をラベルにしたいときは `::text` で文字列にする。
- 結果が 0 行のとき（何も起きていないとき）は No Data になるので、ルールの「No Data のとき」を **Normal** にする。
- ダッシュボードの変数はアラートでは使えないので、時間の範囲はクエリ内に直接書く。
- 「消えた」は、行が結果から外れたこと（自動解決）では表さず、`last_seen` が一定の窓に入った行として明示的に選ぶ。エージェントが止まっただけの場合を除くため、相手側のホストが観測を続けていることを条件に入れる。

実装は `packaging/grafana/provisioning/alerting/shawk-rules.yaml` にある。二回のレビュー（§11, §12）を受けて、次の形になった。

- 全行の `time` を `now()` にそろえて `ORDER BY` する（Grafana は時刻順でない行を拒み、時刻のそろわない系列は最新の時刻にしか値を持たない）。reduce は null を落とす。
- 新しい依存と消えた依存は、サービス単位の `dependency_changes_between` から作る。以前に見たことのある依存（`known_dependencies`）は「新しい」としない。サービス名のない相手は Prometheus と同じ名前（`peer_cidrs` の名前、`~unresolved`、`~external`）にまとめる。
- 新しい依存の窓は 5 分前で終える。新しい接続の両側が書き込まれてからにするため。

```sql
-- 新しい依存（20〜5 分前に初めて見た、以前に見たことのない依存）
SELECT now() AS time, client_service, server_service, port::text AS port, proto, 1 AS value
FROM shawk_v1.dependency_changes_between(now() - interval '20 minutes', now() - interval '5 minutes')
WHERE change = 'appeared'
ORDER BY 1, 2, 3, 4, 5;

-- 消えた依存（30〜15 分前を最後に見えなくなり、それを見ていたホストは観測を続けている）
SELECT now() AS time, client_service, server_service, port::text AS port, proto, 1 AS value
FROM shawk_v1.dependency_changes_between(now() - interval '30 minutes', now())
WHERE change = 'disappeared' AND time <= now() - interval '15 minutes'
ORDER BY 1, 2, 3, 4, 5;

-- 24 時間を超えて報告が途絶えたエージェント（それまでは Prometheus の ShawkAgentDown が受け持つ）。
-- 同じ名前で入れ直されて生きているホストは除き、host_id をラベルにする。
SELECT now() AS time, a.host, a.host_id,
       round(extract(epoch FROM now() - a.last_heartbeat) / 60)::float8 AS value
FROM shawk_v1.agents a
WHERE NOT a.alive
  AND a.last_heartbeat < now() - interval '24 hours'
  AND a.last_heartbeat > now() - interval '30 days'
  AND NOT EXISTS (SELECT FROM shawk_v1.agents b WHERE b.host = a.host AND b.last_heartbeat > a.last_heartbeat)
ORDER BY 1, 2, 3;
```

Prometheus のアラート：

```yaml
# OTLP の push には scrape の up がないので、過去 24 時間にいたのに今いないホストを探す。
# push された系列は最後のサンプルから 5 分で見えなくなる（staleness マーカーがない）ので、
# 停止から約 5 分後に発火し、24 時間後に自動で解決する。それ以降は上の SQL のアラートが受け持つ。
- alert: ShawkAgentDown
  expr: |
    group by (host_name) (max_over_time(shawk_agent_up[24h]))
      unless group by (host_name) (shawk_agent_up)
- alert: ShawkFlowsDropped
  expr: increase(shawk_agent_flows_dropped_total[10m]) > 0
- alert: ShawkConnectionFailureRate
  expr: |
    shawk:dependency_connection_failures:rate5m
      / (shawk:dependency_connections:rate5m + shawk:dependency_connection_failures:rate5m) > 0.05
```

通知ポリシーは、デプロイ直後にまとまって出る新規依存を一通にまとめるため、グルーピングのキーに `client_service` を加える。

## 7. OBI との関係

OpenTelemetry eBPF Instrumentation（OBI）を土台にできるかを検討した（2026-10-31 時点。OBI v1.0.0 は 2026-10-30 に公開）。

### 7.1 結論

- **shawk のトレーサを OBI で置き換えることはできない。** OBI のネットワークフローと TCP 統計には、どのプロセスの通信かという情報がない。これは「一部のフックでは PID の判定が当てにならない」という理由による意図的な設計である。アプリ層の追跡はプロセスを特定できるが、OBI が解析できるプロトコル（約 20 種）に限られ、未知の TCP や UDP の通信は扱わない。
- **構成上の位置づけは OBI に合わせた。** 計装（shawk agent、OBI）は OTLP を出すだけにし、関係の保存と名前の付与は Collector の shawk connector が受け持つ（§2, §4）。
- **採用した形**：OBI をアプリ層の計装として shawk と並べて動かす。OBI の Collector receiver は shawk の Collector に組み込まない（alpha で依存関係が重く、Grafana Alloy も 2026 年 7 月に同じプロセスへの組み込みをやめている）。shawk のトレーサを OBI の新機能として寄与する計画はない。

### 7.2 shawk に必要なものと OBI v1.0.0

| shawk に必要なもの | OBI v1.0.0 |
|---|---|
| 任意のプロトコルについて、どのプロセスがどのサービスと通信しているか | ✗ ネットワークフローと TCP 統計はホスト単位。アプリ層は解析できるプロトコルだけ |
| 同じホスト内のプロセス間の通信 | ✗ 送信元と宛先が同じ IP のパケットと `lo` を除外している |
| 待ち受けポートの一覧、初めて見た時刻 | ✗（待ち受けポートは開発版にだけ一部あり） |
| エージェント起動前からの接続 | △ アプリ層は次のリクエストから追う |
| UDP のクライアントとサーバの区別 | ✗ 向きは unknown |
| 接続失敗・再送・RTT | △ ホスト単位。RTT は切断時にだけ出る。失敗にはリセットやタイムアウトでの切断も含まれる |
| サービス名を `/proc/PID/environ` の `OTEL_SERVICE_NAME` から決める | ◯ 同じ方式（ただしアプリ層で計装したプロセスだけ） |
| HTTP・gRPC・DB などの RED、トレース、サービスグラフ | ◯ shawk にない機能 |
| 安定性 | ネットワークと統計のメトリクスは development 扱いで v1 の互換性の対象外。フローの属性名は改名予定（#1092）。Go の API と Collector の receiver は v0／alpha |

### 7.3 名前のそろえ方

- **サービス**：
  - 両者とも、環境変数（`OTEL_SERVICE_NAME`、`OTEL_RESOURCE_ATTRIBUTES`）、次に実行ファイル名の順で決める（§3.3）。
  - Prometheus では両者とも resource の `service.name` が `job` になるので、同じサービスは同じ `job` で引ける（§4.3）。
  - Java などで食い違う場合は `OTEL_SERVICE_NAME` でそろえる。
- **ホスト**：
  - resource の `host.id`（machine-id）と `host.name` を、両者とも Prometheus で昇格させる。OBI のネットワークと統計のメトリクスは `host.name` を持たないが、アプリ層のメトリクスでは両方が使える。
  - テンプレートから複製した VM は machine-id が同じことがある。PostgreSQL の `hosts.id` は、現行の実装と同じく machine-id とホスト名のハッシュにして区別し、`machine_id` 列を OBI との突き合わせに使う。OBI 側は `host.id` が衝突するので、複製した VM では machine-id を作り直すよう運用で勧める（`systemd-machine-id-setup`）。
- **属性名**：semconv（`network.transport`, `server.port`, `service.peer.name` など）にそろえる。OBI のフローの属性名（`src.*`, `dst.*`）は改名予定なので、そろえない。

### 7.4 並走の構成

**OBI の役割を絞る**

- OBI にはアプリ層（`application` と `application_service_graph`）だけを任せる。
- ネットワークフロー（`network`）と TCP 統計（`stats*`）は有効にしない。理由は二つある。
  - shawk がプロセス単位で同じものを取っている。
  - `stats_tcp_io` はすべての TCP の送受信を観測し、負荷が高いと OBI 自身が注意している。
- OBI はアプリ層の計装を、対象の選び方（selector）を設定したときだけ有効にする。Config v1 の環境変数で対象を指定すれば、ネットワークと統計は既定で無効のままになる。
- Config v2 を使う場合は、`capture.policy.default_action` を省略すると全プロセスが対象になるので、必ず明示する。

**対象のプロセスの選び方**

- OBI は systemd のユニットや cgroup では対象を選べない。待ち受けポート（`OTEL_EBPF_OPEN_PORT`）か実行ファイルのパス（`OTEL_EBPF_AUTO_TARGET_EXE`）で選ぶ。
- 待ち受けポートで選ぶと、同じポートを開くヘルパーやポート転送のプロセスを拾うことがある。
- shawk の `shawk_v1.service_endpoints` には、ホストごとの待ち受けポートとサービスの一覧がある。OBI の対象ポートはここから選べる（自動生成は P1 以降）。
- OBI は既定で、自分で OTLP を送っているプロセスを計装しない（`exclude_otel_instrumented_services`）。SDK で計装済みのサービスとは重ならない。

**各ホストでの動かし方**（Rocky Linux 9。OBI v1.0.0 は RPM がなく、tar 玉とコンテナイメージで配られている）

- バイナリを `/usr/local/bin/obi` に置き、リポジトリの `contrib/obi@.service`（`EnvironmentFile=/etc/obi/%i.env` を読む systemd のテンプレート）で動かす。
- このテンプレートは root で動き、権限を絞っていない。アプリ層の計装に要る権限は `CAP_BPF`, `CAP_DAC_READ_SEARCH`, `CAP_CHECKPOINT_RESTORE`, `CAP_PERFMON`, `CAP_NET_RAW`, `CAP_SYS_PTRACE` である。
- SELinux（enforcing）での動作は OBI の文書にないので、shawk と合わせて検証する。

```sh
# /etc/obi/app.env（systemctl enable --now obi@app）
OTEL_EBPF_OPEN_PORT=8080,8443
OTEL_EBPF_METRICS_FEATURES=application,application_service_graph
# Collector の otlp はクライアント証明書を求める（§4.6）。OBI は OpenTelemetry SDK の変数で証明書を渡す
OTEL_EXPORTER_OTLP_ENDPOINT=https://collector.example:4318
OTEL_EXPORTER_OTLP_CERTIFICATE=/etc/obi/tls/collector-ca.crt
OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE=/etc/obi/tls/obi.crt
OTEL_EXPORTER_OTLP_CLIENT_KEY=/etc/obi/tls/obi.key
```

OBI は既定で 60 秒ごとにメトリクスを送る。アプリ層のダッシュボードは OBI のクエリの最小間隔を 1 分にしている（`$__rate_interval` が 4 分になる）。短くしたいときは `OTEL_EBPF_METRICS_INTERVAL` を設定する。

**Collector**

- OBI の OTLP は通常の受け口（`otlp`）に、shawk agent の OTLP は専用の受け口（`otlp/shawk`）に送る。
- メトリクスは同じ Prometheus へ、トレースは Tempo などへ送る（§4.6）。OBI のメトリクスは batch しない。点の時刻はホストの時計のままなので、時計の大きくずれたホストが一つあると、同じ batch の他のホストの点まで Prometheus に拒まれるため（§12）。

**Grafana でのつなぎ方**

- ダッシュボードの変数 `$service` を `job` から作れば、shawk の依存（`shawk:dependency_*` の `src`/`dst`、PostgreSQL の `client_service`/`server_service`）と OBI の RED を同じ値で絞り込める。
- 依存マップのノード（PostgreSQL）から、そのサービスの OBI の RED とトレースへデータリンクで移る（未実装。§8）。

**アプリ層の計装が届いていない依存を見つける**

shawk が見ている依存のうち、OBI のサービスグラフに現れないもの：

```promql
group by (src, dst) (shawk:dependency_connections:rate5m > 0)
unless on (src, dst)
group by (src, dst) (
  label_replace(label_replace(
    rate(traces_service_graph_request_total[5m]),
    "src", "$1", "client", "(.*)"), "dst", "$1", "server", "(.*)")
)
```

注意点：

- OBI は名前を解決できない相手を、既定で `outgoing`（クライアント側から見た相手）と `incoming`（サーバ側から見た相手）に畳む。そのため、計装していない相手への依存は、この式では「届いていない」側に出る。それは正しい結果である（その相手のアプリ層は見えていない）。
- サービスグラフの `client`/`server` には namespace が付かない。`service.namespace` を使うと `job` は `namespace/name` になるので、突き合わせの前に namespace を外す。
- OBI のサービスグラフと各メトリクスは development 扱いで、v1 の互換性の対象外である。OBI の版を上げるときはこの式とダッシュボードを確かめる。

## 8. この案に入れていないこと（P1 以降）

- 日ごとの活動（`edge_days`）。依存マップの線の太さ、途絶アラートの基準、月次バッチのような稀な依存の判定に使う。
- `host_addrs` の多対多化とスコープ（VIP、コンテナのブリッジ、ループバック）、`0.0.0.0` の待ち受けポートの展開。
- conntrack による NAT の解決と、ロードバランサの VIP → 実サーバの対応表。
- connector の冗長化（loadbalancing exporter による振り分けの設定例、DB 停止時に溜める量の上限）。
- エージェント側の送信キューのディスクへの退避（任意）。
- プロセスのバージョン履歴（`service.version` の切り替わりの注釈）。
- Java などで OBI と同じ名前の決め方（Spring Boot の名前、JAR 名）を取り入れるか。
- `service_endpoints` から OBI の対象ポート（`OTEL_EBPF_OPEN_PORT`）を生成する仕組み。
- Rocky Linux 9 の実カーネル（SELinux enforcing）での CI。
- アプリ層のダッシュボードの gRPC・DB の RED とトレース、依存マップのノードから OBI の RED とトレースへのデータリンク（§6.1, §7.4。今回の実装は HTTP の RED だけ）。

## 9. 実装で決めたこと

実装の途中で決めた細部を記録する（設計の大筋は変えていない）。

### 9.1 エージェント

- OTLP の送り方は gRPC（既定）と HTTP/protobuf（`-otlp-protocol=http/protobuf`）の二つ。どちらも gzip で圧縮する。送り先は `-otlp-endpoint`（URL。`http://` は平文、`https://` は TLS。`-otlp-ca-file` で CA を指定できる）。既定値は環境変数 `OTEL_EXPORTER_OTLP_ENDPOINT` / `OTEL_EXPORTER_OTLP_PROTOCOL`、なければ `http://localhost:4327` と gRPC。
- 一回の送信の時間切れは送信間隔の 2/3（§12 で、リクエストごとに、収集の後から数えるようにした）。送信は再試行しない（次の送信が累積値で追いつく）。部分的な拒否（partial success）も失敗として数える。
- エッジの系列は (役割, プロトコル, ローカルアドレス, 相手アドレス, ポート, netns, ユニット, comm, 実行ファイルのパス, `service.name`, `service.namespace`) で区別する。プロセスが `/proc` を読む前に終了した場合（短命なバッチなど）は、同じ (ユニット, comm) の直近の名前を使う。それもなければ comm を名前にする。
- `first_seen` と `last_seen` は、活動があった区間の終わりの時刻にする。
- TCP のエッジは `connection.opened`、`connection.count`、`network.io`、`tcp.retransmits`、`tcp.rtt` を、クライアント側だけ `connection.failed` も送る。UDP のエッジは `network.io` と `udp.datagrams` を送る。
- `-idle-ttl` は 2 分以上かつ送信間隔の 4 倍以上でなければならない（区間の始まりの規則が「TTL − 1 分」を使うため）。
- `-bpf-stats` は残し、BPF プログラムの実行回数と実行時間を `shawk.agent.bpf.run_count` / `shawk.agent.bpf.run_time`（属性 `shawk.bpf.program`）として送る。HTTP API がなくなったため。
- エージェントの HTTP API（`internal/agent/http.go`）はこの段階で消した。
- `host.ip` には、インタフェースのアドレスに加えて、生きている系列のローカルアドレス（コンテナの名前空間のもの）を入れる（§12 で、直近に活動した系列と開いている待ち受けのものだけにした）。
- machine-id がないホストでは `host.id` を送らない（現行の boot_id への代替はやめた。再起動のたびに別のホストになるため）。

### 9.2 shawk connector

- Go のモジュールは `collector/`（`github.com/yuuki/shawk/collector`）。部品は `collector/shawkconnector`、独自ビルドのマニフェストは `collector/builder-config.yaml`（`make collector`）。エージェントとの OTLP の形の一致は、エージェントのテストが書き出す `collector/shawkconnector/testdata/agent-request.json` を connector のテストが読むことで確かめる（二つのモジュールは互いに依存しない）。
- `hosts.id` は connector が resource の `host.id` と `host.name` から求める（`sha256(machine-id + "\n" + hostname)` の先頭 8 バイト。現行の hostID と同じ）。
- PostgreSQL の `processes.service_name` には Prometheus の `job` と同じ形（`namespace/name`）を入れる。`shawk_v1` のビューの `client_service` / `server_service` と recording rule の `src` / `dst` がそのまま一致する。
- スキーマは `collector/shawkconnector/migrations/` の SQL を埋め込み、`shawk-migrate` コマンド（`make shawk-migrate`）か connector の `postgres.migrate: true` で当てる。適用済みの版は `shawk.schema_migrations` に残す。接続文字列は `postgres.dsn` か `postgres.dsn_file`。
- connector の起動時に DB に届かなくても Collector は起動する。変化は手元に溜め、名前は前回読んだもの（なければ区分）で付ける。
- `service.peer.name` の決め方の細部：
  - ループバックの相手は同じホストとみなす。名前は同じホストの待ち受け（クライアント側）か同じホストのクライアント側のエッジ（サーバ側）だけで引き、`shawk.peer.agent` は true にする。
  - 同じアドレスとポートに複数のサービスが見つかったら、同じホストのもの、次に最も新しく見たものを選ぶ。
  - `peer_cidrs` の値はカンマ区切りで複数の範囲を書ける。`~` で始まる名前は使えない。
  - 区分 `~unresolved` の「プライベート範囲」は、RFC 1918、ループバック、リンクローカル、CGNAT（100.64.0.0/10）、IPv6 ULA。
- 累積値の合算の細部：
  - connector が起動する前に始まった入力系列は、最初の値を基準にして差分 0 とする（再起動直後に過去の累計が一度に足されて率が跳ねないように）。§12 で、そのホストの直近の区間がこの connector で閉じた後に始まった系列だけを全量とする規則に変えた。
  - `shawk.connection.count`（開いている接続）は差分をとらず、入力の現在値の和にする。入力がなくなった出力は 0 になる。§12 で、閉じる区間の値だけを足すようにした。
  - `max_peers` の枠は、出力の TTL の間使われなかった相手から空く。`~other` 自体は枠に数えない。
- 出力のリソースには `service.name`、`service.namespace`（あれば）、`service.instance.id`（= `host.name`）、`host.id`、`host.name` を付ける。エージェント自身のメトリクスは `service.name=shawk-agent` のリソースで、`shawk.agent.segment.start` を除いて転送する。
- `shawk_v1` のビューの細部：
  - `service_endpoints` は、待ち受けポート（`0.0.0.0` は同じホストの IPv4 アドレスに、`::` は全アドレスに展開する）とサーバ側のエッジの（ローカルアドレス, ポート）から作る。当初は直近 7 日に見たものだけを返していたが、§10 の未決事項を受けて、各ホストの「最後に分かっていた待ち受け」を返すように変えた（マイグレーション 0006）：そのホストの最新の待ち受けの報告から 1 時間以内の待ち受け（同じエージェントの時計どうしで比べる）、同じく 7 日以内のサーバ側のエッジ、直近 30 日に報告したホストに限る。アドレスを別のホストが後から持ち始めた場合（生存の窓 5 分より後。ループバックは除く）は、古いホストの名前を返さない。列 `host_id` と `last_seen` を加えた。§8 の「`0.0.0.0` の待ち受けポートの展開」のうち、ホストのアドレスへの単純な展開だけを先に入れた（これがないと、ほとんどのサーバの名前が引けないため）。
  - `agent_addrs` は、直近 5 分以内に報告したホストのアドレスだけを返す（§12 で、区間を閉じたリクエストのハートビートでも判定するようにした）。クライアント側のエージェントが止まると、サーバ側の系列は 5 分ほどで `shawk_peer_agent` が false に変わり、依存単位の値に数えられるようになる。
  - `client_endpoints` は、直近 1 時間に見たクライアント側のエッジ（クライアントのアドレス、サーバのアドレス、ポート、クライアントのサービス）を返す。サーバ側のエッジはクライアント側のエッジが生きている間だけ送られるので、1 時間で足りる。
  - `dependencies` に `client_addr` と `server_unit` を加えた。ループバックのアドレスどうしは、同じホスト・同じ netns のエッジだけを突き合わせる。
  - `graph_nodes` / `graph_edges` / `dependency_changes` はサービス単位にまとめる。サービス名のない相手はアドレスをノードの名前にする（§12 で、Prometheus と同じ `peer_class()` の名前に変えた）。`dependency_changes` の「消えた」は、その依存を見ていたホストが `last_seen` から 15 分以上観測を続けていることを条件にする。
  - `unobserved()` は `SECURITY DEFINER` にした（読み取りのロールが `shawk` スキーマの表を読めなくても使えるように）。
  - `agents` に `host_id`、`machine_id`、`kernel`、`agent_version` を加えた。

- 保持期間（§10 から解決）：connector の設定 `retention`（既定 3 年。0 なら消さない）より前に最後に見た行を、1 時間ごとに関数 `shawk.prune(cutoff, max_rows)`（マイグレーション 0003）で消す。一回の呼び出しで表ごとに最大 1 万行だけ消し、0 行になるまで短いトランザクションで繰り返す。プロセスとホストは参照がなくなってから消す。区間（`agent_sessions`）も消すので、`unobserved()` は保持期間より前を「観測していない」と返す。基準の時刻は PostgreSQL の `now()`。connector のロールには DELETE 権限が要る（`grants.sql`）。

- 時計（§10 から解決）：`last_heartbeat` と、ホストとアドレスの `last_seen` は connector がリクエストを受け取った時刻にする。生死（`agents.alive`、`agent_addrs`）は connector と PostgreSQL の時計だけで判定される。リクエストのデータ点の時刻との差を `agent_sessions.clock_skew`（マイグレーション 0004）に残し、`agents` ビュー、フリートのダッシュボード、Grafana のアラート（1 分を超えて 15 分続いたら）で示す。エッジ・待ち受けポート・プロセスの時刻と区間の始まりはエージェントの時計のまま（区間の始まりは `agent_sessions` のキーなので、揺れる補正はかけない）。

- 共有されるアドレス（§10 から一部解決）：生きている複数のホストが同時に持つアドレス（docker0 の 172.17.0.1 など）は、ホストをまたいで引かない。connector は `agent_addrs` と受け取ったリクエストから、そのアドレスを持つホストが二つ以上あれば同じホストの待ち受けとクライアント側のエッジだけで名前を引き、自ホストも持っていれば相手は自ホスト（`shawk.peer.agent=true`）とみなす。`dependencies` ビューは、二つ以上のホストが重なる期間に持っていたアドレス（`shawk.shared_addrs`。期間は生存の窓 5 分だけ広げる）を含むエッジを同じホストの中だけで突き合わせる（マイグレーション 0005）。エージェントがアドレスのスコープ（bridge・veth・netns）を送る仕組みは §8 の P1 のまま残す。

- 期間で絞る関数（§10 から解決）：`shawk_v1.dependencies_between(since, until)`、`graph_edges_between`、`graph_nodes_between`、`dependency_changes_between` を加えた（マイグレーション 0007。`SECURITY DEFINER`）。期間に活動したエッジだけを先に索引で絞ってから突き合わせる。100 万エッジ（うち直近 1 時間に活動 2 万）で、30 分の窓が 3.2 秒 → 0.27 秒、依存マップ（6 時間）が 3.3 秒 → 0.21 秒になった。同梱のダッシュボードと SQL のアラートはこれらを使う。ビューは互換のために残す。`dependency_changes_between` の「現れた」は、期間に活動したエッジの中での `first_seen` で判定する（§12 で、`known_dependencies` に前からある依存を除くようにした）。

### 9.3 packaging

- 置き場所：`packaging/prometheus/`（`shawk-rules.yml`、`prometheus.yml`）、`packaging/grafana/`（`dashboards/` と `provisioning/`）、`packaging/collector/config.yaml`、`packaging/postgres/`（`setup.sql`、`grants.sql`）、`packaging/systemd/`（エージェントと Collector のユニット、`agent.env`）。
- recording rule は §4.4 の二つに加えて、`shawk:dependency_open_connections`、`shawk:dependency_request_bytes:rate5m` / `shawk:dependency_response_bytes:rate5m`（クライアントからサーバ / サーバからクライアント。クライアント側の transmit とサーバ側の receive を同じ向きとして扱う）、UDP の `shawk:dependency_request_datagrams:rate5m` / `shawk:dependency_response_datagrams:rate5m`、`shawk:dependency_rtt_seconds_sum:rate5m` / `_count:rate5m`、`shawk:dependency_retransmits:rate5m`（`shawk_role` を残す）を作る。
- Prometheus のアラートに `ShawkUDPNotTraced` と `ShawkExportFailures` を加えた。
- Grafana の SQL のアラート「新しい依存」「消えた依存」は、行ごとではなくサービス単位（`dependency_changes_between`）で判定する。行ごとに判定すると、レプリカの一つが入れ替わっただけで発火するため。観測を続けている側は、クライアント側に限らず両側の `observed_until` の大きい方で判定する（クライアントにエージェントがない依存も扱えるように）。現在の形は §6.2。
- ダッシュボードは五つ（フリート、依存マップ、依存の詳細、変化、アプリ層（OBI））。データソースは uid `shawk-postgres` / `shawk-prometheus` で参照する。依存マップは変数 `service`（複数可）、`direction`（downstream / upstream / both）、`depth` を持ち、再帰 SQL は（サービス, 深さ）の `UNION` で辿り、深さの上限を入れる（§12）。
- エージェントの `shawk.agent.up` と `shawk.agent.udp.traced` は単位を空にした。単位 `1` の Gauge には Prometheus が `_ratio` を付けるため。
- 見本のテスト：recording rule とアラートは `test/packaging`（独自の go.mod）で Prometheus の PromQL エンジンに合成した系列を読ませて値を確かめる。ダッシュボードの PromQL は構文と recording rule の名前を確かめる。ダッシュボードと SQL アラートの SQL は、`grants.sql` を当てたうえで `shawk_grafana` ロールで実際の PostgreSQL に流す（Grafana のマクロは置き換える）。Grafana そのものでの読み込みは確かめていない。

### 9.4 廃止と文書

- `internal/ledger`、`internal/query`、`internal/client`、`internal/api`、`internal/agent/http.go`、CLI の問い合わせコマンドと `modernc.org/sqlite` への依存を消した。CLI は `agent`、`flows`、`version` だけになった。
- e2e テスト（`test/e2e/run.sh`、`make e2e`）は、ネットワーク名前空間の三つのホストのエージェントを、ocb で作った Collector と PostgreSQL（`SHAWK_E2E_POSTGRES_DSN`）につなぎ、`shawk_v1` のビューと転送したメトリクスを確かめる形に書き直した。三つのホストは machine-id を共有するので、複製した VM の区別も確かめている。
- CI（`.github/workflows/test.yml`）は PostgreSQL のサービスコンテナを使い、`make test`（三つのモジュール）と `make e2e` を動かす。
- deb / rpm には `/etc/shawk/agent.env`（設定ファイル）を加えた。
- Collector の配布（§10 から解決）：goreleaser の before フックで ocb を `--skip-compilation` で動かし（マニフェストの `dist.version` をリリースの版に置き換える）、生成した `collector/_build` を goreleaser がビルドする。エージェントと同じタグで、アーカイブと deb / rpm の `shawk-collector`（`/usr/bin/shawk-collector`、`/usr/bin/shawk-migrate`、`shawk-collector.service` と同名のシステムユーザ、`/etc/shawk/collector.yaml`（noreplace）、`/usr/share/shawk-collector/postgres/` の SQL）と、distroless のコンテナイメージ `ghcr.io/yuuki/shawk-collector`（amd64 / arm64。`/shawk-migrate` も入れる）を作る。

## 10. 実装中に見つけた未決事項と解決

| 未決事項 | 状態 | 解決の内容 |
|---|---|---|
| サーバ側の再送の `src`：相手にエージェントがあるサーバ側の系列は `~agent` という名前なので、どのクライアントへの再送か分からない | 解決 | サーバ側でもクライアントのサービス名を `service.peer.name` に入れ（`client_endpoints` からの逆引き）、「相手にエージェントがあるか」を別の属性 `shawk.peer.agent` にした。二重計上の規約は `shawk_peer_agent="false"` で判定する（§4.2, §4.4）。Prometheus の契約にラベルが一つ増えた |
| 共有されるプライベートアドレス（docker0 の 172.17.0.1 など） | 一部解決 | 複数の生きているホストが同時に持つアドレスは、名前の引き当てと `dependencies` の突き合わせを同じホストの中だけで行う（§9.2）。エージェントがアドレスのスコープ（bridge・veth・netns）を送る仕組みは §8 の P1 のまま |
| `service_endpoints` の期間（7 日を過ぎると名前が引けない） | 解決 | 各ホストの最後に分かっていた待ち受けを返す。30 日報告のないホストと、別のホストに移ったアドレスは除く（§9.2） |
| 保持期間 | 解決 | connector の `retention`（既定 3 年）と `shawk.prune()`（§9.2） |
| `dependencies` ビューの重さ | 解決 | 期間で絞る関数 `*_between(since, until)` を加え、同梱のダッシュボードとアラートはそれを使う（§9.2） |
| 時計のずれ | 解決 | 生死は connector の受信時刻で判定し、ずれを `clock_skew` に残してアラートする（§9.2）。エッジの時刻はエージェントの時計のまま（NTP を前提にする） |
| Collector の配布 | 解決 | goreleaser が ocb の生成したソースを同じ版でビルドし、deb / rpm の `shawk-collector`（`shawk-migrate`、systemd ユニット、設定、PostgreSQL のスクリプトを含む）とコンテナイメージ `ghcr.io/yuuki/shawk-collector` を作る（§9.4） |

残っているもの：

- **アドレスのスコープ（§8 の P1）**：コンテナのネットワークのアドレスを一つのホストだけが持つ場合、エージェントのないホストの相手がそのホストのものとして引かれることがある。エージェントが `host.ip` をスコープつきで送り、`host_addrs` に `scope` 列を足す形で解決する。
- **サーバ側の名前が付くまでの遅れ**：新しいクライアントの最初の数十秒（クライアント側のエッジが connector に届くまで）は、サーバ側の相手が `~unresolved` になる。`shawk.peer.agent` は正しいので、依存単位の値は変わらない。

## 11. 敵対的レビューとその対応（2026-10-31）

四つの領域（エージェント、connector、SQL、ルール・ダッシュボード・配布）を、それぞれ独立したサブエージェントにレビューさせた。指摘はすべて、コード・SQL・計測・Grafana の SDK で検証してから直した。「確認」は、レビュアーとは別に再現して確かめたもの。

| 指摘 | 妥当性 | 対応 |
|---|---|---|
| 1 リクエストにすべての系列を入れるため、約 1,400 エッジで gRPC の受信上限（既定 4 MiB）を超え、以後送れなくなる | 確認（1 エッジ約 3 KB、1,400 エッジで 4.17 MB） | エージェントは `-max-series-per-request`（1000）ごとに分けて送り、最後のリクエストにエージェント自身のメトリクスを入れて区間を閉じる。connector は最後のリクエストで出力する。設定例の受信上限も 16 MiB に上げた |
| 同じ cgroup・comm で `OTEL_SERVICE_NAME` だけ違うプロセスを区別できない | 妥当（カーネルのフローの鍵に PID がない） | 当初の制約どおり tracer は変えず、限界として文書に書いた。PostgreSQL 側の取り違え（`processes` が (unit, comm) で一意）は直した（鍵に `service_name` を加えた。マイグレーション 0008） |
| 所有者不明のソケットの `service.name` が空 | 妥当 | ユニット、次に `~unknown` にする |
| OTLP のエンドポイントの扱いが OTel の慣例と違う、http:// で CA を指定しても黙って無視 | 妥当 | `/v1/metrics` を常に付ける、既定のポートをプロトコルで変える、http:// で TLS の指定はエラー。クライアント証明書（mTLS）も加えた |
| `/proc/PID/environ` の読み取りにタイムアウトがない | 妥当（仕組みは正しい。この環境では未再現） | 200 ms の期限。期限を過ぎたプロセスは直前の名前を使い、読み取りが戻るまで読み直さない |
| 遅れて届いた・再送されたリクエストをリセットとみなし、累計を二重に数える | 確認 | 入力点ごとに時刻を持ち、新しくない点は無視する。出力は区間ごとに一度だけ |
| `shawk.peer.agent` が 15 分（idle TTL）残る、ホスト名の変更でアドレスが共有扱いになる | 確認 | 生存の窓（5 分）で判定し、3 分以上前に報告をやめた持ち主は「移った」とみなす |
| UDP を追跡しないエージェントの相手も「エージェントあり」になる | 妥当 | UDP のエッジでは相手のエージェントの `udp_traced` も条件にする（`agent_addrs` に列を加えた） |
| 一つの netns だけを追跡するエージェントの相手も「エージェントあり」になる | 一部だけ妥当 | `-netns self`（コンテナの中など）ではその netns のアドレスしか報告しないので、判定は正しい。誤るのは、ルート netns から別の netns を追跡する場合（追跡しないインタフェースのアドレスを報告していた）だけ。エージェント側で、追跡しない netns のアドレスを `host.ip` に入れないようにした（レビュアーの案のように netns_scope で一律に外すと、`-netns self` の構成で二重計上になる） |
| 1 リクエストの処理がフリート全体に比例する | 妥当 | 出力をホストごとに持つ。1 万ホストでも 1 リクエスト約 5 µs。書き込みと名前の読み直しの期限も分けた |
| 同点の名前の候補がランダムに選ばれる | 妥当 | 同じホスト、ソケットで観測したもの（`exact`）、新しさ、名前の順で決める |
| zone 付き IPv6 が一つあるとそのホストの書き込みが永久に止まる | 妥当 | zone を外す。データの誤り（SQLSTATE 22, 23）で拒否された変化は捨てる |
| 基準値の判定でエージェントと connector の時計を混ぜている | 妥当 | エージェントの時計に換算して比べる |
| 同じ範囲を別名で書いた `peer_cidrs`、短すぎる `idle_ttl` を受け付ける | 妥当 | 設定の検証で拒否する（`idle_ttl` は 2 分以上） |
| SQL のアラートが 2 行以上でエラー（時刻順でない）、または最新の系列しか発火しない | 確認（Grafana の SDK の `LongToWide` で再現） | 全行の時刻を `now()` にそろえ、`ORDER BY`、reduce は `dropNN` |
| 「新しい依存」がレプリカ一つで発火、名前のない相手が空のラベルに畳まれる | 確認 | サービス単位の `dependency_changes_between` から作る。`proto` もラベルにした |
| 時計が進んだエージェントがあると `unobserved()` が全ホストで失敗する | 確認 | 区間の始まりを `clock_skew` で connector の時計に換算する |
| `shared_addrs` が素早い再利用を永久に共有とみなす、全組み合わせの結合で遅い | 妥当（1,000 ホスト × 21 アドレスで 6 秒） | 10 分以上同時に持っていたら共有、EXISTS で書き直した（22 ms） |
| `service_endpoints` が手放したアドレスにも展開する、全サーバ側エッジを走査する | 妥当（100 万エッジで 4.6 秒） | 現在のアドレスにだけ展開、サーバ側エッジはホストごとに索引で読む、「移ったアドレス」はアドレスごとの集計で判定（0.8 秒） |
| `prune` が待っている間に更新された行を消す | 確認（旧版で再現） | 外側の DELETE にも条件を繰り返す |
| connector がマイグレーションの履歴を書き換えられる | 妥当 | `grants.sql` で取り消す |
| 同梱のエージェント設定（https）と Collector 設定（平文）がつながらない、受け口に認証がない | 確認 | `otlp/shawk` を TLS ＋クライアント証明書にし、エージェントの例もそれに合わせた |
| `grants.sql` を文書どおり `shawk_owner` で流すと `ALTER ROLE` で失敗する | 確認 | `ALTER ROLE` を superuser で流す `setup.sql` に移した |
| ダッシュボードの変数が TCP からしか作られず、`$service` にサーバ専用のサービスが出ない | 妥当 | 変数を TCP と UDP の両方、`$service` を `job` から作る。UDP のパネルも加えた |
| 依存の詳細の SQL が OR で絞っている、計装の抜けのパネルが namespace を外していない、沈黙アラートの文面に 1 が出る | 妥当 | それぞれ直した |
| コンテナで `shawk-migrate` を動かす例、`GOBIN` 設定時の ocb、存在しない `roles.sql`、非推奨の exporter 名 | 妥当 | それぞれ直した（ocb は `go run` で起動、exporter は `otlp_http` / `otlp_grpc`） |

テストの穴も埋めた。

- アラートの SQL は、複数行を返す状況で、行の時刻がそろっていてラベルの組が重ならないことを確かめる。
- `grants.sql` は、スキーマの持ち主のロールで流す。
- ダッシュボードの変数とパネルの PromQL は、合成した系列で評価して、UDP の依存、サーバ専用のサービス、namespace 付きのサービスを確かめる。
- 新しいテストは、古いファイルに対して失敗することを確かめた。

## 12. 二回目の敵対的レビューとその対応（2026-11-01）

§11 の対応の後、同じ四つの領域をもう一度、独立したサブエージェントにレビューさせた。指摘はコード・SQL・計測で確かめてから直し、直したものにはそれぞれ回帰テストを足した。新しいテストは、直す前の動き（直した箇所を一つずつ元に戻したもの）では失敗することを確かめた。

| 指摘 | 妥当性 | 対応 |
|---|---|---|
| 一区間の一部のリクエストしか届かないと（最後のリクエストが届かない）、ハートビートも出力もないのに、`host_addrs` がリクエストごとに新しくなり、相手からは「エージェントあり」に見え続ける | 確認 | アドレスは区間を閉じるリクエストからだけ記録する（connector の手元と `host_addrs` の両方）。`agent_addrs` はハートビートでも判定し、列 `last_heartbeat` を加えた（マイグレーション 0009）。エージェントは、送信の期限を収集の後から、リクエストごとに数える |
| リクエストを系列の数だけで分けているので、IPv6 と長い実行ファイルのパスでは 1000 系列で 4 MiB を超える | 確認（4.47 MB） | 系列ごとの大きさを見積もり、3 MiB も超えないように分ける |
| 活動のない系列のアドレスが idle TTL の間 `host.ip` に残り、移ったアドレスが共有扱いになる | 妥当 | 直近 2 区間（1 分以上）に活動した系列と、開いている待ち受けのアドレスだけを送る |
| 分割したとき、クライアント側のエッジが同じホストの待ち受けより先に届き、最初の区間の相手が `~unresolved` になる | 確認 | 待ち受け、サーバ側のエッジ、クライアント側のエッジの順に送る |
| `/proc/PID/environ` の読み取りの期限が直列で、送信の期限を食う。遅いだけのプロセスは毎区間読み直す | 妥当 | 8 並列、区間あたり 1 秒の予算で読む。期限を過ぎたプロセスは、読み取りが戻ってから 5 分読まない |
| 所有者不明の待ち受け（`~unknown`）を connector は名前として覚えるが、PostgreSQL は返さない | 妥当 | `~unknown` は名前として覚えない |
| 再利用された PID のプロセスの名前を付けることがある | 妥当（頻度は未確認） | `/proc/PID/comm` がフローの comm と一致しなければ信用しない（tracer の comm はメインスレッドのもので、`/proc/PID/comm` と同じ） |
| comm が 15 バイトで多バイト文字の途中で切れると、protobuf の Marshal が失敗し、その区間が毎回送れない | 確認 | 不正な UTF-8 を置き換えてから送る |
| エージェントの時計が後ろに戻ると、そのホストの出力が止まり、その間に期限切れになった入力が後で二重に数えられる | 確認 | ホストの最新のリクエストより 2 分以上古いリクエストは時計が戻ったとみなし、入力の次の点を基準にし直して、次の区間を出力する |
| 別の connector に振り分けられたホストの系列が、それまでの累計を一度に足す | 確認 | 初めて見る入力は、そのホストの直近の区間がこの connector で閉じた後に始まったものだけを全量とする。まだ閉じていないホストでは、connector の起動後かつ直近 2 分以内に始まったものだけ |
| DB に読めない間、DB から読んだエージェントが時計とともに期限切れになり、`shawk_peer_agent` が false に変わって二重計上になる | 確認 | DB から読んだ時刻は、読んだ時点で判定する（読めない間は年齢を止める）。`write_interval` は 1 分以下、エージェントの `-interval` も 1 分以下に制限した |
| データの誤りで捨てた変化の中のエッジが二度と書かれず、区間がその欠落を隠す。DB の停止中に connector が止まると、溜めた変化が失われるのを区間が隠す | 妥当 | 捨てたホストの受理済みの記録を忘れ、エージェントがまだ送っているものを書き直す。connector が初めて見たホストと、変化を捨てたホストの区間は、エージェントの idle TTL の最小値（2 分）より前には始めない。その間は観測の空白として残る |
| 最後のリクエストが失われた区間の開いている接続数が、名前の変わった次の区間に重なって二重になる | 確認 | 閉じる区間の時刻の値だけを足す |
| Prometheus へのエラーをエージェントに返し、DB には書けているのに送信の失敗として数えさせる | 妥当 | ログに出して（1 分に一度）エージェントには返さない |
| 出力の時刻がエージェントの時計なので、時計の大きくずれたホストが一つあると、Prometheus が batch ごと拒み、他のホストの点も失われる | 確認（Prometheus の OTLP ハンドラで 400） | 出力（転送するエージェントのメトリクスも）は connector の時計の時刻にする。OBI のパイプラインからは batch を外した |
| ルートの netns で `-netns self` を使うと、コンテナの通信を追跡しないのにホストのアドレスを報告し、相手からは追跡済みに見える | 妥当（推論のみ） | エージェントが起動時に警告し、限界として文書に書いた（ホストの通信の二重計上と、コンテナの通信の数え漏れのどちらかを選ぶことになるため、判定は変えていない） |
| 「新しい依存」が、しばらく使われなかった既知の依存が新しいエッジ（新しいコンテナ、毎時のジョブ）で戻っただけで発火する | 確認 | これまでに見た依存を `known_dependencies` に残し（connector が 5 分ごとに `shawk.refresh_known_dependencies()` で更新。DB の停止や時計の遅れに備えて 1 時間の重なりを取る）、それに前からある依存は「現れた」としない |
| サービス名のない相手をアドレスで名付けるので、アドレスの変わるクラウドの API などで、アドレスごとに「新しい」「消えた」が出る | 確認 | `shawk_v1.peer_class()` で Prometheus と同じ名前（`peer_cidrs` の名前、`~unresolved`、`~external`）にまとめる。connector は `peer_cidrs` を `shawk.peer_cidrs` に書く。依存マップのノードも同じ名前になる |
| 期間の端で、片側のエッジだけが期間に入り、相手がアドレスで名付けられた片側だけの行が出る（幻の新しい依存、幻のノード） | 確認 | 15 分の余裕をとってエッジを取り出し、突き合わせてから期間で絞る。新しい依存のアラートの窓は 5 分前で終える |
| `host_addrs` が最初と最後の時刻しか持たないので、A→B→A と移ったアドレスが保持期間の間ずっと共有扱いになり、B が「移った」とも判定されない | 確認 | `host_addrs` を期間ごとの行にした（5 分見えなければ新しい期間）。`service_endpoints` の「移った」はホストごとの最新の期間で判定する |
| 依存マップの再帰が経路を数え上げ、ハブのあるグラフの深さ 5 で爆発する | 確認（300 サービス、ハブ 2 つで 8.2 秒） | （サービス, 深さ）の `UNION` で辿る（43 ms） |
| `dependency_changes_between` が突き合わせを二度評価する | 妥当 | `MATERIALIZED` の CTE で一度にした |
| 沈黙したエージェントのアラートが、同じ名前で入れ直されて生きているホストに出る。最初の 24 時間は Prometheus のアラートと二重に出る | 確認 | 新しい行のある同名のホストを除き、`host_id` をラベルにした。24 時間を超えたものだけにした |
| 依存の詳細の SQL が `peer_cidrs` の名前の相手を拾えない | 確認 | `peer_class()` で名付けて絞る |
| `unobserved()` が区間の始まりを最新のずれで換算する | 妥当 | 換算の側ではなく、エージェントが区間の始まりを現在の時計で送るようにした（時計が飛んでも、送る値は単調時計で測った経過時間から求める） |
| connector がスキーマの版を確かめない。0008 のロックの順序が `prune` と逆でデッドロックする | 確認 | `migrate: false` の connector は `shawk.schema_version()` で版を確かめ、古ければ書き込みを待つ。書き込みと `prune` はマイグレーションの advisory lock を共有で取り、マイグレーションと互いに待つ |
| OBI の既定の送信間隔（60 秒）だと、アプリ層のパネルの `rate` が空になる | 確認 | OBI のクエリの最小間隔を 1 分にした |
| 認証のない `otlp` の受け口から `shawk_agent_up` を偽造して、アラートを黙らせられる | 妥当 | `otlp` にもクライアント証明書を求める。OBI は OpenTelemetry SDK の変数で証明書を渡す（OBI v1.0.0 のメトリクスの送信は SDK の設定を上書きしないことをソースで確かめた） |
| 同梱の Collector 設定の mTLS と受信上限を確かめるテストがない。計装の抜けのパネルのテストが空の場合だけ。二つのアラートを評価していない | 確認 | テストを足し、CI で `shawk-collector validate` も流す |
| 設計案（§4.6, §6.1, §6.2, §7.4, §9.3）が直す前の設定や SQL、実装していない機能を載せたまま | 確認 | 書き直し、実装していないものは §8 に移した |
| TLS の鍵を Collector の利用者が読めなければならないことが書かれていない | 妥当 | `packaging/README.md` に書いた |

残っているもの：

- **ルートの netns だけを追跡するエージェント**：警告と文書だけ。コンテナのあるホストでは `-netns all` を使う。
- **大きな表に索引を作るマイグレーション**：0008 は `edges` に `CONCURRENTLY` なしで索引を作る。リリース前なので既存の大きな表はないが、今後のマイグレーションでは索引の作成を分け、手順を文書にする。
- **`known_dependencies` の最初の構築**：0009 は既存の全エッジから一度に作る。大きな既存のデータベースでは、マイグレーションに時間がかかる。
