# shawk 次期設計案：PostgreSQL ＋ OpenTelemetry ＋ Grafana

状態：提案（2026-10-31）。現行の実装（`docs/design.md`）からの変更案であり、まだ実装していない。

[類似ツール比較と設計レビュー](../reports/shawk%20類似ツール比較と設計レビュー.md)で最優先（P0）とした五点を反映済み。

| P0 | 内容 | 反映先 |
|---|---|---|
| 1 | Prometheus のラベルから相手アドレスを外し、相手は `service.peer.name` に一本化する | §3.2, §3.3 |
| 2 | 使われなくなった系列を 15 分で送るのをやめ、相手数に上限を設ける | §3.4 |
| 3 | 両端で記録した同じ依存の計上規約を決め、二重計上をなくす | §3.5, §4.3 |
| 4 | エージェントの観測区間を残し、「使われていない」と「観測していない」を区別する | §4.2, §4.3 |
| 5 | Postgres のアラートを時系列形式で組み、空の結果を Normal にし、消滅は明示的な行で表す | §5.2 |

## 1. 目的と範囲

- 画面は Grafana（または同等のダッシュボード・アラートツール）だけにする。CLI の問い合わせコマンド（`who-uses`, `deps`, `can-i-remove`, `unused`, `diff`, `graph`, `status`）とエージェント間の HTTP API は廃止する。
- shawk が外に約束するもの（契約）は二つだけにする。
  - PostgreSQL の `shawk_v1` スキーマのビューと関数（§4）
  - メトリクスの名前と属性（§3）
- Grafana のダッシュボード、アラートルール、Prometheus の recording rule は、この契約の使い方の見本として `packaging/grafana/` と `packaging/prometheus/` に同梱する。
- `shawk flows`（そのホストのフローをその場で見るデバッグ用の CLI）は残す。DB は使わない。

## 2. 構成

```
 各ホスト
 eBPF ─ agent ─┬─ 15 秒ごと  OTLP ─→ Collector ─→ Prometheus 互換ストア ─┐  数値
               │      ↑ service.peer.name を付けて送る                    │
               │      └── 自分の通信相手の分だけ参照 ──┐                  ▼
               └─ 1〜5 分ごと  変化分の upsert ──→ PostgreSQL ────────→ Grafana
                                  ＋ハートビート      関係・観測区間
```

- eBPF による収集は現行のまま（TCP は `inet_sock_set_state` とソケットイテレータ、UDP は fentry、カーネル内で依存単位に束ね、15 秒ごとに回収する）。
- 「依存が存在するか」は PostgreSQL を正、「どれだけ流れたか」は Prometheus を正とする。両者は名前（`service.name`, `service.peer.name`, `server.port`, `network.transport`, `host.name`）でつなぎ、DB をまたいだ結合はしない。

## 3. メトリクスの契約

### 3.1 メトリクス

| OTel の名前 | 種類・単位 | Prometheus 上の名前 | 内容 |
|---|---|---|---|
| `shawk.connection.opened` | Counter, `{connection}` | `shawk_connection_opened_total` | 確立した接続 |
| `shawk.connection.failed` | Counter, `{connection}` | `shawk_connection_failed_total` | 接続の失敗（クライアント側だけで観測できる） |
| `shawk.connection.count` | UpDownCounter, `{connection}` | `shawk_connection_count` | 区間の終わりに開いていた接続 |
| `shawk.network.io` | Counter, `By` | `shawk_network_io_bytes_total` | 送受信バイト。`network.io.direction` = `transmit` / `receive` |
| `shawk.udp.datagrams` | Counter, `{datagram}` | `shawk_udp_datagrams_total` | UDP の送受信数。`network.io.direction` つき |
| `shawk.tcp.retransmits` | Counter, `{segment}` | `shawk_tcp_retransmits_total` | 自分の送信の再送 |
| `shawk.tcp.rtt` | Histogram（境界なし）, `s` | `shawk_tcp_rtt_seconds_sum` / `_count` | 平滑化 RTT の標本。平均は `_sum` ÷ `_count` |

エージェント自身のメトリクス（相手の属性は付けない）：

| OTel の名前 | Prometheus 上の名前 | 内容 |
|---|---|---|
| `shawk.agent.up` | `shawk_agent_up` | 動いている間 1 を送り続ける。停止検知に使う |
| `shawk.agent.flows.dropped` | `shawk_agent_flows_dropped_total` | フロー表があふれて捨てた更新 |
| `shawk.agent.udp.traced` | `shawk_agent_udp_traced` | UDP を追跡できているか（0/1） |
| `shawk.agent.peers.overflow` | `shawk_agent_peers_overflow_total` | 相手数の上限を超えて `~other` に畳んだ回数 |
| `shawk.agent.db.pending` | `shawk_agent_db_pending` | DB にまだ書けていない変化の件数 |
| `shawk.agent.db.write.duration` | `shawk_agent_db_write_duration_seconds` | DB への書き込み時間（Histogram） |

- カウンタは累積（cumulative）で送る。Prometheus の delta 対応は実験段階のため。
- RTT は境界なしの Histogram にすることで、`_sum` と `_count` の 2 系列（と `le="+Inf"` の 1 系列）だけで平均が求まる。分位が必要になったらネイティブヒストグラムを任意で有効にする。

### 3.2 属性

| 属性 | 置き場所 | Prometheus 上のラベル | 値 |
|---|---|---|---|
| `host.name` | resource | `host_name` | ホスト名。Prometheus の `promote_resource_attributes` で昇格させる |
| `service.name` | resource | `job` | エージェント自身（`shawk-agent`） |
| `service.name` | データ点 | `service_name` | 観測した**ローカルの**プロセスのサービス名（§3.3） |
| `service.peer.name` | データ点 | `service_peer_name` | 相手のサービス名、または集約した区分（§3.3） |
| `shawk.role` | データ点 | `shawk_role` | `client`（自分が接続した）/ `server`（自分が受け付けた） |
| `server.port` | データ点 | `server_port` | サービスポート（役割にかかわらず常にサーバ側のポート） |
| `network.transport` | データ点 | `network_transport` | `tcp` / `udp` |
| `network.peer.address` | データ点 | `network_peer_address` | **既定では送らない**。`-metrics-peer-address` で有効化したときだけ |

- 相手の IP アドレスは既定のラベルに入れない（P0-1）。正確なアドレスは PostgreSQL の `edges` にある。
- `network.io.direction` は送受信の向きにだけ使い、クライアントかサーバかの役割には使わない（semconv の定義に従う）。役割は `shawk.role` で表す。
- Prometheus 側の設定：`--web.enable-otlp-receiver`、`promote_resource_attributes: [host.name]`、`out_of_order_time_window: 30m`。

### 3.3 ローカルと相手の名前の決め方

ローカルの `service.name` は、次の順で最初に得られたものを使う。

1. プロセスの環境変数の `OTEL_SERVICE_NAME`、または `OTEL_RESOURCE_ATTRIBUTES` の `service.name`（`/proc/PID/environ` から `OTEL_` で始まる変数だけを読み、他は捨てる）
2. cgroup から求めた systemd ユニット名（`nginx.service` など。一時的な名前は現行どおり正規化する）
3. プロセス名（comm）

`service.peer.name` は役割によって決め方が違う。

| 役割 | 相手 | `service.peer.name` |
|---|---|---|
| client | 相手のアドレスとポートで待ち受けているサービスが PostgreSQL の `service_endpoints` で分かる | そのサービス名 |
| client | 分からないが、設定した名前付き CIDR に入る | その名前（例 `office-lan`） |
| client | 分からず、プライベート範囲 | `~unresolved` |
| client | 分からず、それ以外 | `~external` |
| server | 相手のアドレスがエージェントのいるホストのもの | `~agent`（クライアント側の系列が正。§3.5） |
| server | それ以外 | 名前付き CIDR、`~unresolved`、`~external` の順 |

- 区分の値は `~` で始める。実在のサービス名と衝突させないため。
- 名前付き CIDR は `-peer-cidrs` で設定する（例 `office-lan=192.168.10.0/24,dc-a=10.1.0.0/16`）。最も狭い範囲が勝つ。
- エージェントは、自分が通信している相手の `(アドレス, ポート)` だけを数分ごとに `shawk_v1.service_endpoints` と `shawk_v1.agent_addrs` から引き、手元に保持する。DB に届かない間は最後に得た対応を使い続ける。
- 新しいエッジは、相手の名前を一度引こうとしてから送り始める。最初だけ `~unresolved` で出て、すぐ別の系列に切り替わる揺れを避けるため。
- ラベルは「送った時点の最善の推定」であり、帰属の正は PostgreSQL だと文書に明記する。

### 3.4 系列数の上限

- **アイドル系列の破棄**：15 分（`-metrics-idle-ttl`）活動のなかったエッジは、送るのをやめて状態も捨てる（P0-2）。再び現れたらカウンタは 0 から始まる。初回の増分が `increase()` に乗らないことがあるが、依存が存在したことは PostgreSQL に残る。
- **相手数の上限**：`(service.name, shawk.role)` ごとに、`service.peer.name` の値を最大 50 種類（`-metrics-max-peers`）までとし、超えた分は `~other` に畳む。畳んだ回数は `shawk_agent_peers_overflow_total` に出す。
- **系列数の目安**：エッジ系列の数は「ローカルのサービス × 相手のサービス（または区分）× ポート × 役割」で決まり、相手のレプリカ数や IP の入れ替わりには増えない。
- Collector の `transform` プロセッサの `limit()` は安全網として置くだけにし、削減はエージェント内で済ませる。

### 3.5 二重計上の規約

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

## 4. PostgreSQL の契約

### 4.1 テーブル（内部。`shawk` スキーマ）

PostgreSQL 14 以上を前提とする（多重範囲型 `tstzmultirange` と再帰問い合わせの `CYCLE` 句を使う）。

```sql
CREATE TABLE shawk.hosts (
  id            text PRIMARY KEY,          -- 安定したホスト ID（machine-id など）。名前は説明属性
  hostname      text NOT NULL,
  kernel        text NOT NULL,
  agent_version text NOT NULL,
  first_seen    timestamptz NOT NULL,
  last_seen     timestamptz NOT NULL
);

-- エージェントが観測できていた区間（P0-4）
CREATE TABLE shawk.agent_sessions (
  host_id        text NOT NULL REFERENCES shawk.hosts,
  started_at     timestamptz NOT NULL,     -- エージェントの起動時刻
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

書き込みの規則：

- エッジ・listener・プロセス・アドレスは変化した分だけ upsert する。`first_seen = least(...)`、`last_seen = greatest(...)` なので、順序の入れ替わりや再送があっても結果は同じになる。
- `agent_sessions.last_heartbeat` は、書き込みのたびに（変化がなくても）その書き込みに含めた最新の観測時刻へ進める。DB が止まっている間は進まず、復旧後にまとめて書けた時点で一気に進む。その間にエージェントが再起動すれば、溜めていた変化は失われ、旧セッションの `last_heartbeat` から新セッションの `started_at` までが観測の空白として残る。
- `dropped_flows` は、そのセッションでカーネルが捨てたフロー更新の累計。0 でなければ、その区間の記録は不完全である。

### 4.2 観測区間（P0-4）

```sql
-- [since, until] のうち、ホストが観測できていなかった区間
CREATE FUNCTION shawk_v1.unobserved(since timestamptz, until timestamptz,
                                    tolerance interval DEFAULT '10 minutes')
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

- `tolerance` は書き込み周期の 2 倍程度にする。
- Grafana では、この関数を注釈（`time` と `timeend`）として全パネルに重ねると、観測の空白が網掛けで見える。

### 4.3 契約のビュー（`shawk_v1` スキーマ）

| ビュー | 主な列 | 用途 |
|---|---|---|
| `dependencies` | `client_host`, `client_service`, `client_unit`, `server_host`, `server_service`, `server_addr`, `port`, `proto`, `first_seen`, `last_seen`, `observed_by`, `client_observed_until`, `server_observed_until` | 論理的な依存 1 件を 1 行にしたもの |
| `graph_nodes` / `graph_edges` | Node Graph が要求する列（`id`, `title`, `subtitle`, `mainstat` / `id`, `source`, `target`, `mainstat`） | 依存マップ |
| `dependency_changes` | `time`, `change`（appeared / disappeared）, `client_service`, `server_service`, `port` | 変化の表と注釈 |
| `service_endpoints` | `addr`, `port`, `proto`, `host`, `service` | エージェントが `service.peer.name` を引く |
| `agent_addrs` | `addr`, `host` | エージェントがサーバ側の `~agent` を判定する |
| `agents` | `host`, `started_at`, `last_heartbeat`, `udp_traced`, `netns_scope`, `dropped_flows`, `alive` | エージェントの状態 |

`dependencies` の組み立て（P0-3）：

- クライアント側の `edges`（`role='client'`）とサーバ側の `edges`（`role='server'`）を、アドレスの組（`client.local_addr = server.remote_addr`, `client.remote_addr = server.local_addr`）とポートで突き合わせ、1 件にまとめる。
- `observed_by` は、両側で見えていれば `both`、片側だけなら `client` か `server`。片側だけの依存は、相手にエージェントがないか、間に NAT やロードバランサがあることを示す。
- `first_seen` は両側の小さい方、`last_seen` は大きい方。
- `client_observed_until` と `server_observed_until` は、それぞれのホストの最新の `last_heartbeat`（P0-4）。`last_seen` が古くても `client_observed_until` が新しければ「本当に使われていない」。両者が近ければ「エージェントが止まって見えなくなった」可能性がある。

権限：

- Grafana には `shawk_v1` の SELECT 権限だけを持つロールを使い、`statement_timeout` と `default_transaction_read_only` を設定する。
- エージェントの書き込みは自ホストの行に限る（ホストごとのロールと行単位の権限、または SECURITY DEFINER 関数）。詳細は P1。

## 5. Grafana

### 5.1 ダッシュボード

| ダッシュボード | 主なデータ源 |
|---|---|
| フリート概要（エージェントの稼働、観測の空白、ドロップ、UDP 未追跡、今日増えた依存） | Postgres（`agents`, `unobserved()`）、Prometheus（`shawk_agent_*`） |
| 依存マップ（対象と深さを変数で選ぶ。再帰 SQL に `CYCLE` 句と深さの上限を入れる） | Postgres（`graph_nodes`, `graph_edges`） |
| 依存の詳細（接続数、失敗率、再送、RTT と、両端・初めて見た時刻・最後に見た時刻・観測区間） | Prometheus（recording rule）、Postgres（`dependencies`） |
| 変化（現れた依存・消えた依存を表と注釈で） | Postgres（`dependency_changes`） |

### 5.2 アラート（P0-5）

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
  AND client_observed_until > now() - interval '10 minutes'
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

## 6. OBI との関係

OpenTelemetry eBPF Instrumentation（OBI）を土台にできるかを検討した（2026-10-31 時点。OBI v1.0.0 は 2026-10-30 に公開）。調査の詳細は `research_notes/OBI土台化の検討/` にある。

### 6.1 結論

- **shawk のトレーサを OBI で置き換えることはできない。** OBI のネットワークフローと TCP 統計には、どのプロセスの通信かという情報がない。これは「一部のフックでは PID の判定が当てにならない」という理由による意図的な設計である。アプリ層の追跡はプロセスを特定できるが、OBI が解析できるプロトコル（約 20 種）に限られ、未知の TCP や UDP の通信は扱わない。
- **一方で、構成上の位置づけとしては OBI を土台にすべきである。** 計装は OTLP を出すだけにし、関係の保存（PostgreSQL）と Grafana の見本を shawk の本体とする。そうすれば、OBI と shawk を同じ Collector に並べられ、将来は shawk のトレーサを OBI の機能に差し替える道も開ける。

### 6.2 shawk に必要なものと OBI v1.0.0

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

### 6.3 選択肢

| 選択肢 | 評価 |
|---|---|
| (a) OBI と shawk を並べて動かし、名前をそろえる | 最小のリスクですぐできる。OBI がアプリ層、shawk が L4 のプロセス単位の依存を受け持つ |
| (b) OBI の Collector receiver と shawk の部品を一つの Collector に組み込む | 可能だが、alpha の receiver と OBI の依存関係（約 226 モジュール、生成済み eBPF コードの差し替え）に縛られる。Grafana Alloy も 2026 年 7 月に Beyla を同じプロセスに組み込むのをやめ、子プロセスとして動かす形に戻している |
| (c) shawk のトレーサを OBI の新機能として上流に寄与する | 実在する空白を埋める（opentelemetry-network は 2026 年 10 月にアーカイブ済み）。ただし、プロセス単位の帰属について SIG の合意が要る。また OBI の流儀（kprobe 中心、Config v2、スキーマ登録、広いカーネル試験）への書き直しと、eBPF コードのライセンス（OBI は Apache-2.0 ヘッダで Dual MIT/GPL）の整理が前提になる |
| (d) shawk のトレーサを OBI で置き換える | v1.0.0 では不可（6.2） |
| (e) shawk の関係の書き込みを Collector 側の部品（shawk connector）に移し、エージェントは OTLP を出すだけにする | (a) の上に重ねる新案。下で説明する |

### 6.4 推奨

1. **いま**：(a)。OBI をアプリ層に、shawk を L4 のプロセス単位の依存に使い、両方の OTLP を同じ Collector に送る。名前は semconv と OBI のサービス識別（`service.name`、`host.id`）にそろえる。OBI のフローの属性名（`src.*`, `dst.*`）にはそろえない（改名予定のため）。
2. **次**：(e)。エージェントは、エッジごとの詳細（アドレス、プロセスの属性）を OTLP で出すだけにする。shawk connector を組み込んだ Collector（OBI の receiver は含めない独自ビルド）が、次の三つを受け持つ。
   - PostgreSQL への関係の書き込みと `agent_sessions` の更新（その送信分の関係と同じトランザクションで書く）
   - `service.peer.name` と `~agent` の付与（`service_endpoints` と `agent_addrs` を一か所でキャッシュする）
   - アドレスを落とした数値を Prometheus へ転送する
3. **長期**：(c)。プロセス単位の依存を記録する機能を OBI の SIG に提案する（v1.0 の告知が 2027 年の計画への意見を募っている）。受け入れられれば shawk のエージェントは退役でき、shawk は connector と PostgreSQL の契約と Grafana の見本だけになる。

(e) で得られるもの：

- エージェントが DB の資格情報を持たなくてよくなる（行単位の権限の問題が消える）。
- 1000 台のエージェントがそれぞれ DB に問い合わせる代わりに、connector が一か所で引く。
- 計装（shawk のエージェント、将来の OBI）と保存（shawk connector）の境界が OTLP になり、計装を差し替えても保存側は変わらない。

(e) の代償：

- 独自ビルドの Collector を配布・運用する必要がある。
- connector は状態（関係の変化の間引き、名前のキャッシュ）を持つ。書き込みは冪等なので複数台に増やせる。

### 6.5 本文への影響

- §3.2：resource の `host.id`（`/etc/machine-id`）も `promote_resource_attributes` で昇格する。OBI のネットワークと統計のメトリクスは `host.name` を持たず `host.id` だけを持つので、両者をつなぐ鍵になる。`shawk.hosts.id` にも同じ値を使う。
- §3.3：OBI の `service.name` は環境変数がなければ実行ファイル名になり、shawk の systemd ユニット名とずれる。両者を一致させたいサービスには `OTEL_SERVICE_NAME` を設定するよう勧める（systemd のドロップインの `Environment=` で足りる）。shawk には `-service-name-fallback=unit|exe` を用意する。
- (e) を採る場合は §2、§3.3（名前の参照先）、§4.1（書き込みの主体と権限）を書き換える。

## 7. この案に入れていないこと（P1 以降）

- 日ごとの活動（`edge_days`）。依存マップの線の太さ、途絶アラートの基準、月次バッチのような稀な依存の判定に使う。
- `host_addrs` の多対多化とスコープ（VIP、コンテナのブリッジ、ループバック）、`0.0.0.0` の listener の展開。
- conntrack による NAT の解決と、ロードバランサの VIP → 実サーバの対応表。
- 書き込み経路の強化（`last_seen` の更新を粗くする、行単位の権限、コネクションプーラ、ローカルのスプール）。
- プロセスのバージョン履歴（`service.version` の切り替わりの注釈）。
- Rocky Linux 9 の実カーネル（SELinux enforcing）での CI。
