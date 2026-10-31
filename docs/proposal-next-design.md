# shawk 次期設計案：PostgreSQL ＋ OpenTelemetry ＋ Grafana

状態：提案（2026-10-31）。現行の実装（`docs/design.md`）からの変更案であり、まだ実装していない。

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
| `host.id` | `/etc/machine-id`（OBI と同じ取り方） |
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

- 同じホストで同じ実行ファイル（`ruby`、`python`、`java`、`php-fpm` など）を使う別々のサービスは、環境変数で名前を与えない限り、Prometheus の数値では同じ `service_name` に混ざる。PostgreSQL では `shawk.unit` で区別できる。
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

connector は PostgreSQL の `shawk_v1.service_endpoints` と `shawk_v1.agent_addrs` を手元に保持する。1 分ごとに読み直し、自分が書いた変化もその場で反映する。`service.peer.name` は次のように決める。

| 役割 | 相手 | `service.peer.name` |
|---|---|---|
| client | 相手のアドレスとポートで待ち受けているサービスが `service_endpoints` で分かる | そのサービス名 |
| client | 分からないが、設定した名前付き CIDR に入る | その名前（例 `office-lan`） |
| client | 分からず、プライベート範囲 | `~unresolved` |
| client | 分からず、それ以外 | `~external` |
| server | 相手のアドレスがエージェントのいるホストのもの（`agent_addrs`） | `~agent`（クライアント側の系列が正。§4.4） |
| server | それ以外 | 名前付き CIDR、`~unresolved`、`~external` の順 |

- 区分の値は `~` で始める。実在のサービス名と衝突させないため。
- 名前付き CIDR は connector の設定 `peer_cidrs` で与える。最も狭い範囲が勝つ。
- 名前は「集約した時点の最善の推定」であり、帰属の正は PostgreSQL だと文書に明記する。
- 新しいサーバの待ち受けポートが PostgreSQL に入るまで（最大 1 分）は、クライアント側が `~unresolved` で出て、その後サービス名に切り替わることがある。

### 4.3 Prometheus に届くメトリクス

connector は §3.1 の「集約して転送」のメトリクスを、次の属性だけに減らして合算する。エージェント自身のメトリクスはそのまま転送する。

| 属性 | Prometheus 上のラベル |
|---|---|
| resource の `host.id` / `host.name` | `host_id` / `host_name`（Prometheus の `promote_resource_attributes` で昇格させる） |
| resource の `service.name`（`shawk-agent`） | `job` |
| `service.name` | `service_name` |
| `service.peer.name` | `service_peer_name` |
| `shawk.role` | `shawk_role` |
| `server.port` | `server_port` |
| `network.transport` | `network_transport` |
| `network.io.direction`（バイトと UDP のみ） | `network_io_direction` |

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
| 接続数、開いている接続、バイト数、UDP 数、RTT | クライアント側を正とする。サーバ側は相手にエージェントがない場合（`service_peer_name != "~agent"`）だけ使う |
| 接続の失敗 | クライアント側だけ（サーバには届かないため） |
| 再送 | 両側を使う。各ソケットが自分の送信を再送した数なので重複ではない。`shawk_role` で送信側を区別する |

サーバ側の `~agent` 系列とクライアント側の系列は重ならないように作ってあるので、依存単位の値は和集合をとるだけで求まる。依存単位の系列は recording rule で作り、ダッシュボードとアラートはこれを使う。

```yaml
groups:
  - name: shawk-dependencies
    rules:
      - record: shawk:dependency_connections:rate5m
        expr: |
          sum by (src, dst, server_port, network_transport) (
              label_replace(label_replace(
                rate(shawk_connection_opened_total{shawk_role="client"}[5m]),
                "src", "$1", "service_name", "(.*)"), "dst", "$1", "service_peer_name", "(.*)")
            or
              label_replace(label_replace(
                rate(shawk_connection_opened_total{shawk_role="server", service_peer_name!="~agent"}[5m]),
                "dst", "$1", "service_name", "(.*)"), "src", "$1", "service_peer_name", "(.*)")
          )
      - record: shawk:dependency_connection_failures:rate5m
        expr: |
          sum by (src, dst, server_port, network_transport) (
            label_replace(label_replace(
              rate(shawk_connection_failed_total{shawk_role="client"}[5m]),
              "src", "$1", "service_name", "(.*)"), "dst", "$1", "service_peer_name", "(.*)"))
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

```yaml
receivers:
  otlp/shawk:                 # shawk agent 専用の受け口
    protocols:
      grpc: { endpoint: 0.0.0.0:4327 }
  otlp:                       # OBI など
    protocols:
      grpc: { endpoint: 0.0.0.0:4317 }

connectors:
  shawk:
    postgres:
      dsn_file: /etc/shawk/postgres-dsn
    write_interval: 1m
    idle_ttl: 15m
    max_peers: 50
    peer_cidrs:
      office-lan: 192.168.10.0/24

processors:
  batch: {}

exporters:
  otlphttp/prometheus:
    endpoint: http://prometheus:9090/api/v1/otlp

service:
  pipelines:
    metrics/shawk-in:         # connector の前に batch を置かない（一回の送信を一区間として扱うため）
      receivers: [otlp/shawk]
      exporters: [shawk]
    metrics/shawk-out:
      receivers: [shawk]
      processors: [batch]
      exporters: [otlphttp/prometheus]
    metrics/obi:
      receivers: [otlp]
      processors: [batch]
      exporters: [otlphttp/prometheus]
```

## 5. PostgreSQL の契約

### 5.1 テーブル（内部。`shawk` スキーマ）

PostgreSQL 14 以上を前提とする（多重範囲型 `tstzmultirange` と再帰問い合わせの `CYCLE` 句を使う）。

```sql
CREATE TABLE shawk.hosts (
  id            text PRIMARY KEY,          -- host.id（machine-id）。名前は説明属性
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

CREATE TABLE shawk.host_addrs (
  host_id    text NOT NULL REFERENCES shawk.hosts,
  addr       inet NOT NULL,
  first_seen timestamptz NOT NULL,
  last_seen  timestamptz NOT NULL,
  PRIMARY KEY (host_id, addr)
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
| `agent_addrs` | `addr`, `host` | connector がサーバ側の `~agent` を判定する |
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
| 依存マップ（対象と深さを変数で選ぶ。再帰 SQL に `CYCLE` 句と深さの上限を入れる） | Postgres（`graph_nodes`, `graph_edges`） |
| 依存の詳細（接続数、失敗率、再送、RTT と、両端・初めて見た時刻・最後に見た時刻・観測区間） | Prometheus（recording rule）、Postgres（`dependencies`） |
| 変化（現れた依存・消えた依存を表と注釈で） | Postgres（`dependency_changes`） |
| アプリ層（HTTP・gRPC・DB の RED とトレース） | OBI のメトリクスとトレース |

### 6.2 アラート（P0-5）

Grafana の PostgreSQL データソースは、アラートの条件に**時系列形式**のクエリしか使えないと文書化されている（表形式でも動くとする文書もあり、食い違っている。対象の Grafana で確かめるまでは時系列形式で組む）。そのため、SQL のアラートは次の形にそろえる。

- `time` 列、ラベルにする文字列の列、数値の `value` 列を 1 つ返す。数値をラベルにしたいときは `::text` で文字列にする。
- 結果が 0 行のとき（何も起きていないとき）は No Data になるので、ルールの「No Data のとき」を **Normal** にする。
- ダッシュボードの変数はアラートでは使えないので、時間の範囲はクエリ内に直接書く。
- 「消えた」は、行が結果から外れたこと（自動解決）では表さず、`last_seen` が一定の窓に入った行として明示的に選ぶ。エージェントが止まっただけの場合を除くため、相手側のホストが観測を続けていることを条件に入れる。

```sql
-- 新しい依存（15 分以内に初めて見た依存）
SELECT max(first_seen) AS time,
       client_service, server_service, port::text AS port,
       1 AS value
FROM shawk_v1.dependencies
WHERE first_seen > now() - interval '15 minutes'
GROUP BY client_service, server_service, port;

-- 消えた依存（30〜15 分前を最後に見えなくなり、クライアント側は今も観測できている）
SELECT max(last_seen) AS time,
       client_service, server_service, port::text AS port,
       1 AS value
FROM shawk_v1.dependencies
WHERE last_seen BETWEEN now() - interval '30 minutes' AND now() - interval '15 minutes'
  AND client_observed_until > now() - interval '5 minutes'
GROUP BY client_service, server_service, port;

-- 長く報告が途絶えたエージェント（TSDB の保持期間を超えても効く）
SELECT last_heartbeat AS time, host, 1 AS value
FROM shawk_v1.agents
WHERE NOT alive AND last_heartbeat > now() - interval '30 days';
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

- **ホスト**：`host.id` を両者の共通の鍵にする。OBI のネットワークと統計のメトリクスは `host.name` を持たず `host.id` だけを持つ。shawk も `/etc/machine-id` を `host.id` にし、Prometheus で昇格させる。
- **サービス**：両者とも環境変数、次に実行ファイル名の順で決める（§3.3）。Java などで食い違う場合は `OTEL_SERVICE_NAME` でそろえる。
- **属性名**：semconv（`network.transport`, `server.port`, `service.peer.name` など）にそろえる。OBI のフローの属性名（`src.*`, `dst.*`）は改名予定なので、そろえない。
- **将来**：OBI のサービスグラフ（`traces_service_graph_*`、`client`/`server` ラベル）と shawk の `service_name`/`service_peer_name` を PromQL で突き合わせれば、アプリ層の計装が届いていない依存を見つけられる。

## 8. この案に入れていないこと（P1 以降）

- 日ごとの活動（`edge_days`）。依存マップの線の太さ、途絶アラートの基準、月次バッチのような稀な依存の判定に使う。
- `host_addrs` の多対多化とスコープ（VIP、コンテナのブリッジ、ループバック）、`0.0.0.0` の待ち受けポートの展開。
- conntrack による NAT の解決と、ロードバランサの VIP → 実サーバの対応表。
- connector の冗長化（loadbalancing exporter による振り分けの設定例、DB 停止時に溜める量の上限）。
- エージェント側の送信キューのディスクへの退避（任意）。
- プロセスのバージョン履歴（`service.version` の切り替わりの注釈）。
- Java などで OBI と同じ名前の決め方（Spring Boot の名前、JAR 名）を取り入れるか。
- Rocky Linux 9 の実カーネル（SELinux enforcing）での CI。
