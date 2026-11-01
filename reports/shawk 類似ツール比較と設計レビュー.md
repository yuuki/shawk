# shawk 新設計は台帳で勝ち、ラベルで躓く

shawk の新設計は、骨格では業界の定石に沿っている。収集は Coroot・Caretta・opentelemetry-network と同じ「TCP 状態遷移のフックと、起動前からある接続の列挙」の系譜にあり、送受信経路に一切フックしない点で調査したツールのうち最も軽い。数値を OTLP → Collector → Prometheus 互換ストアで流す経路も OBI と同じ形だ。最大の独自性は、first_seen/last_seen を持つ関係台帳を PostgreSQL に分けたことにある。調査した OSS の eBPF ツールはどれも、トポロジを TSDB の系列からその都度計算するか、数時間〜数週間で捨てている。90 日〜1 年の依存履歴と「新しい依存」アラートを持つものはない。この台帳は Dynatrace Smartscape の lifetime や CMDB 型の依存マッピング製品に近い。VM/オンプレ向けの OSS は空白になりつつある（opentelemetry-network は 2026 年 10 月にアーカイブ、Caretta は休眠、Weave Scope は非推奨）。その中で、この台帳ははっきりした強みになる。一方で、危うい逸脱が四つある。第一に、Prometheus のラベルに peer_addr を載せている。ペア×アドレスの次元は、OBI も opentelemetry-network も既定で避けている。第二に、両端で記録した同じ依存の計上規約が決まっていない。Istio/Kiali、Datadog、opentelemetry-network はいずれも片側を正としている。第三に、記録期間（coverage）と時間単位の活動記録を廃止した。そのため「使われていない」と「観測していなかった」を区別できず、依存が途切れていた期間も失う。第四に、NAT/LB の解決を将来課題に回している。VIP やロードバランサの多いオンプレでは、依存がそこで途切れる。Grafana 連携は、Node Graph を SQL で直接供給できる点で Caretta の「PromQL の魔術」より筋が良い。ただし Postgres のアラートは時系列形式しか条件に使えないので、ビューをその制約に合わせて設計する必要がある。最優先の推奨は三つある。メトリクスのラベルを service 対 service の粒度に絞り、peer_addr は Postgres だけに置く。クライアント側を正とする計上規約を recording rule と SQL ビューに埋め込む。エージェントの観測区間と日次の活動を Postgres に小さく残す。

## 11 観点の判定：骨格は定石どおり、逸脱は四点に集まる

比較の物差しを先に示す。下表は、依頼された観点ごとに、先行ツールの定石と shawk 新設計を並べたものである。判定は本文の分析の要約で、詳細と出典は各節にある。

| 観点 | 業界の定石（代表例） | shawk 新設計 | 判定 |
|---|---|---|---|
| データ収集 | TCP 状態遷移＋既存ソケット列挙（Coroot, Caretta, opentelemetry-network）、またはパケット経路＋サンプリング（Hubble, Retina, NetObserv, OBI） | `inet_sock_set_state` ＋ソケットイテレータ、UDP は fentry | 一致。系譜の中で最も軽い |
| 集約 | カーネル内ハッシュマップで束ね、5〜30 秒で回収 | サービスポート＋プロセス身元で束ねて 15 秒で回収 | 一致。プロセス身元を鍵に含む点は強み |
| 保存先の分担 | トポロジは TSDB から都度計算（Coroot, Kiali, Caretta, Tempo）、または専用のエンティティ台帳（Dynatrace, New Relic, CMDB） | Postgres の関係台帳＋TSDB | OSS では独自の強み。ただし coverage と活動記録の廃止は後退 |
| トポロジの組み立て | クエリ時に宛先と listen 情報を結合（Coroot） | SQL ビューで事前に突き合わせ | 一致。0.0.0.0・VIP・アドレスのスコープ処理が要る |
| 両端の突き合わせと二重計上 | 両側で記録し、片側を正とする（Istio の reporter、Datadog、opentelemetry-network） | 両側で記録するが、規約がない | 逸脱（要定義） |
| NAT/LB 解決 | conntrack をフックして NAT 前後を両方保持（Coroot, Datadog, opentelemetry-network） | 将来課題 | 逸脱（オンプレでは優先度が低すぎる） |
| カーディナリティ | アドレスは既定で隠す（OBI）、ペア次元は既定でオフ、アイドル系列は 1〜15 分で破棄 | peer_addr をラベル化、TTL は数値未定 | 危うい逸脱 |
| Grafana 連携 | Node Graph は PromQL で組むか（Caretta）、独自 UI | Postgres の SQL で Node Graph | 強み。SQL アラートには形式の制約がある |
| アラート | ルールのテンプレートを同梱（NetObserv, Coroot） | provisioning で同梱＋新規依存アラート | 一致。新規依存アラートは独自 |
| OTel 規約 | 独自の名前空間＋semconv の属性（OBI） | `peer_service`, `direction`, `host` | 軽微な逸脱（名前を寄せるべき） |
| 運用・プロジェクト状況 | VM 向け OSS は空白化している | VM/オンプレに特化 | 立ち位置は有利。実機での検証が不足 |

## 収集と集約は Coroot と opentelemetry-network の系譜で、最も軽い位置にある

### 状態遷移と既存ソケットの列挙は定石、送受信経路を避ける点が独自

TCP の収集方式は先行例とほぼ同じだ。Coroot の node-agent は `inet_sock_set_state` トレースポイントで成否を数える。CLOSE→SYN_SENT で PID を控え、SYN_SENT→ESTABLISHED を成功、SYN_SENT→CLOSE を失敗とする。エージェント起動前の接続は、起動時に `/proc/net/tcp` と fd を走査して帰属させる（[Coroot blog](https://coroot.com/blog/building-a-service-map-using-ebpf)）。Caretta も同じトレースポイントで役割（クライアントかサーバか）を判定する。既存の接続は `sk_max_ack_backlog` で listen 側かどうかを見分ける（[Caretta blog](https://www.groundcover.com/blog/caretta)）。opentelemetry-network は既存ソケットを `tcp4_seq_show` などで列挙し、UDP では `ip_send_skb` と `skb_consume_udp` をフックしていた（[render_bpf.c](https://github.com/open-telemetry/opentelemetry-network/blob/main/collector/kernel/bpf_src/render_bpf.c)）。**shawk の UDP フックはこれとまったく同じ関数**である。つまり shawk は、TCP では Coroot、UDP では opentelemetry-network の系譜を引いている。

違いは、データ経路を避けた徹底ぶりにある。Caretta は受信セグメントごとに `tcp_data_queue` に kprobe を掛けてバイト数を読む。opentelemetry-network も `tcp_rcv_established`、`tcp_event_data_recv`、`tcp_rtt_estimator` という受信経路に載っている。shawk はバイト数と再送を `tcp_sock` の累積カウンタ（`bytes_acked`, `bytes_received`, `total_retrans`）から、クローズ時とイテレータの走査ごとに差分で読む（[shawk design.md](https://github.com/yuuki/shawk/blob/main/docs/design.md)）。パケット経路で観測するツールは、コストを抑えるためにサンプリングに頼る。NetObserv は既定で 1/50 にサンプリングする（[FlowCollector API](https://github.com/netobserv/network-observability-operator/blob/main/docs/FlowCollector.md)）。Retina は 1/N サンプリングと 30 秒ごとの報告を組み合わせ、perf 配列が 32 コア超のノードで劣化する問題を抱える（[Retina packetparser](https://retina.sh/docs/Metrics/plugins/Linux/packetparser)）。これに対し shawk のバイト数は推定ではなく正確だ。代償として、ソケット層より下のドロップやインタフェース単位の通信は見えない。どのツールの一次資料にもネットワークマップ機能のオーバーヘッドの定量値はなかった。したがって「最も軽い」という主張は、フックの位置からの推論にとどまる。shawk 自身で計測する必要がある。

この系譜から引き継ぐべき教訓は三つある。一つ目に、Caretta は「`sock` 構造体はカーネルに再利用されるため、ライフサイクルを追わないと衝突と誤情報を生む」と警告している（[Caretta blog](https://www.groundcover.com/blog/caretta)）。shawk はソケットのローカルストレージ（`SK_STORAGE`）に向きと鍵を持たせているので、構造的にこの罠を避けている。二つ目に、UDP の fentry はカーネル関数のシグネチャに依存する。Datadog は fentry の読み込みに失敗したときに kprobe へ自動で切り替える仕組みを入れた（[datadog-agent PR #59165](https://github.com/DataDog/datadog-agent/pull/59165)）。shawk にも同じ退路があってよい。三つ目に、RTT の意味の違いがある。Coroot の `container_net_latency_seconds` は ICMP の能動的な計測であり、TCP の RTT ではない（[Coroot docs](https://docs.coroot.com/metrics/node-agent)）。shawk の平滑化 RTT は Datadog と同じ受動的な信号で、Datadog はこれにジッタ（RTT の分散）を添えている（[Datadog Network Analytics](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/network_analytics/)）。

接続失敗の内訳も先行例のほうが細かい。Datadog は Agent 7.59 以降、リセット・拒否・タイムアウトを既定で分け、7.68 以降は到達不能も加えた（[Datadog CNM setup](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/setup/)、[Datadog Network Analytics](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/network_analytics/)）。OBI の `obi.stat.tcp.failed.connections` は `reason` ラベルを持つ（[OBI metrics](https://opentelemetry.io/docs/zero-code/obi/metrics/)）。shawk でも、SYN_SENT→CLOSE の時点でソケットのエラー値を読めば、低カーディナリティの理由ラベルを付けられる見込みがある。ただし、その時点でエラー値が確定しているかは実機での確認が要る。

### カーネル内で束ねる方式は NetObserv v2 と同じ結論、プロセス身元を鍵に含む点が強み

依存単位でカーネル内に束ねる方式は、パケット系ツールも最終的に辿り着いた結論だ。NetObserv の eBPF エージェントは、パケットごとにリングバッファへ送る v1 設計を「ボトルネックとレコード欠損を生む」として捨て、per-CPU ハッシュマップでフローを集約する v2 に移った（[NetObserv ebpf_implementation.md](https://github.com/netobserv/netobserv-ebpf-agent/blob/main/docs/ebpf_implementation.md)）。ただし v2 は、マップが満杯になるとそのレコードをリングバッファでユーザ空間へ送り、即座に退避させる。現行の shawk は `-max-flows` を超えると更新を捨てる（[shawk design.md](https://github.com/yuuki/shawk/blob/main/docs/design.md)）。ドロップをメトリクスで見せる計画はあるが、退避で救えるならそのほうが台帳の完全性に効く。回収間隔の 15 秒も相場どおりだ。NetObserv のオペレータ既定は 15 秒、Retina は 30 秒、Datadog は 30 秒ごとに収集して 5 分単位に集約する（[Datadog Network Analytics](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/network_analytics/)）。

クライアントのエフェメラルポートを捨ててサービスポートで束ねるのも定石である。Coroot は既定で 32768〜60999 のポートを宛先からも listen からも除外する（[Coroot flags.go](https://github.com/coroot/coroot-node-agent/blob/main/flags/flags.go)）。Caretta のリンク鍵は（client, server, server_port, role）だ。プロセス身元を鍵に入れる点も業界の流れに沿う。Coroot は systemd のユニットを「コンテナ」として扱い、VM やベアメタルを同じモデルで覆う（[Coroot requirements](https://docs.coroot.com/installation/requirements)）。DeepFlow は 7.0 から、同じホスト内で同じ cmdline のプロセスを一つの gprocess に束ねている（[DeepFlow 7.0 CE](https://deepflow.io/docs/release-notes/release-7.0-ce)）。Azure Migrate は依存を「送信元サーバ＋プロセス → 宛先サーバ＋プロセス＋ポート」で表す（[Azure Migrate](https://learn.microsoft.com/en-us/azure/migrate/concepts-dependency-visualization)）。一つ確認すべき点がある。鍵の `comm` がスレッド名だと、マルチスレッドのアプリでは同じサービスのエッジがスレッド名ごとに割れうる。OTel のエンティティモデルは、識別属性は不変、説明属性は可変と分けている（[OTel Entity Data Model](https://opentelemetry.io/docs/specs/otel/entities/data-model/)）。これに倣うなら、身元はホストとユニット（cgroup）に置き、`comm`・exe・version は説明属性として扱うのが安全だ。

## Postgres の関係台帳は OSS で唯一の設計だが、捨てようとしている二つの記録が要る

### 都度計算するか台帳を持つか：shawk は商用・CMDB 側に立つ

トポロジの持ち方は二系統に分かれる。一つは、トポロジを保存せずに数値の系列からその都度組み立てる系統だ。Kiali は「バックエンドはストレージを必要としない」と明言している（[Kiali architecture](https://kiali.io/docs/architecture/architecture/)）。Coroot は外向き接続の宛先と `container_net_tcp_listen_info` を IP:PORT で結合してマップを作る（[Coroot blog](https://coroot.com/blog/building-a-service-map-using-ebpf)）。Tempo と Collector の service graph は、スパンの組をメモリ上で突き合わせる（[servicegraphconnector README](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/connector/servicegraphconnector)）。DeepFlow は ClickHouse の `network_map` テーブルに、SkyWalking は時間バケットごとの relation メトリクス行に、Pixie は `conn_stats` にエッジを置き、どれもクエリ範囲ごとに集約し直す（[DeepFlow storage](https://deepflow.io/docs/best-practice/reduce-storage-overhead/)、[SkyWalking TopologyQueryService](https://github.com/apache/skywalking/blob/master/oap-server/server-core/src/main/java/org/apache/skywalking/oap/server/core/query/TopologyQueryService.java)、[Pixie conn_stats](https://docs.px.dev/reference/datatables/conn_stats/)）。

もう一つは、寿命を持つ専用のエンティティ・関係グラフを置き、テレメトリが ID でそれを参照する系統だ。Dynatrace Smartscape のノードは `lifetime.start`（最初に発見された時刻）と `lifetime.end`（最後に観測された時刻）を持つ。`lifetime.end` は観測のたびに upsert で更新され、35 日を過ぎたノードは削除される（[Dynatrace Smartscape on Grail](https://docs.dynatrace.com/docs/discover-dynatrace/platform/grail/smartscape-on-grail)）。**shawk の least/greatest による冪等な upsert と「最後に見てから N 日で削除」は、この規則を長い保持期間で再現したもの**に等しい。OTel のブログも、エンティティイベントを追記型のログとして保存し、変化のない連続観測は「各連続区間の最初と最後」だけを残すよう勧めている（[OTel blog](https://opentelemetry.io/blog/2026/consuming-opentelemetry-entity-events/)）。この設計は風変わりなものではなく、認められた型である。

保持期間の比較が shawk の価値をよく示す。DeepFlow の既定は秒粒度 1 日・分粒度 7 日（[DeepFlow data node](https://deepflow.io/docs/guide/ee-tenant/system/data-node/)）、SkyWalking の `metricsDataTTL` はトポロジを含めて 7 日（[SkyWalking TTL](https://github.com/apache/skywalking/blob/master/docs/en/setup/backend/ttl.md)）、Pixie は「数時間程度」（[Pixie memory](https://docs.px.dev/reference/admin/tuning-mem-usage)）、Datadog CNM は 14 日（[Datadog Network Analytics](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/network_analytics/)）、Dynatrace は 35 日で固定だ（[Dynatrace Smartscape on Grail](https://docs.dynatrace.com/docs/discover-dynatrace/platform/grail/smartscape-on-grail)）。Coroot と Tempo は、アイドルになった系列をそれぞれ 10 分と 15 分で破棄する。shawk の 90 日〜1 年は、これらすべてを超える。VM/オンプレ向けの依存マッピング製品と比べても、shawk の方式は強い。Azure Migrate は 5 分ごとに TCP 接続をポーリングし、6 時間ごとに送信する（[Azure Migrate](https://learn.microsoft.com/en-us/azure/migrate/concepts-dependency-visualization)）。ServiceNow は netstat/ss/lsof に頼り、地図を整えたらトラフィック由来の発見は止めるよう勧めている（[ServiceNow traffic-based discovery](https://www.servicenow.com/docs/bundle/washingtondc-it-operations-management/page/product/service-mapping/concept/traffic-based-discovery.html)）。ポーリングは短命な接続を取りこぼす。カーネル内で常時束ねる shawk は、月次バッチのような稀な依存を逃さない。ここが「この DB を最後に使ったのは誰か」という廃止判断の問いに直結する。

生のフローではなく集約済みの関係を保存する判断も、業界の流れと一致する。NetObserv は Loki を任意にした構成で、メモリ 45〜65% 減、ストレージ約 90% 減を計測した。Prometheus の P90 クエリ遅延は、6 時間の範囲で Loki の 10 秒超に対し 474 ms だった（[Red Hat Developer](https://developers.redhat.com/articles/2024/09/19/lightweight-network-observability-operator-without-loki)）。Isovalent も Timescape 1.18 で、フローイベントを補う「集約され、DB に優しい」接続ログを導入した（[Isovalent INK 1.18](https://isovalent.com/blog/post/isovalent-networking-for-kubernetes-118-new-routing-policy-and-observability-enhancements/)）。台帳の置き場として Postgres を選んだのも妥当だ。SkyWalking は MySQL/PostgreSQL を中規模の本番向けとしている（[SkyWalking storage](https://skywalking.apache.org/docs/main/latest/en/setup/backend/backend-storage/)）。rqlite 用の Grafana プラグイン（g42, v1.1.5）は、変更履歴にアラート・マクロ・時系列への言及がない（[rqlite plugin](https://grafana.com/grafana/plugins/g42-rqlite-datasource/)）。Infinity プラグイン経由のアラートはバックエンドパーサでしか動かない（[Infinity docs](https://grafana.com/docs/plugins/yesoreyeram-infinity-datasource/latest/query/)）。さらに rqlite のクエリは既定でタイムアウトしない（[rqlite API](https://rqlite.io/docs/api/api/)）。Grafana を唯一の UI とするなら、Postgres 推奨は正しい。

### 二つの店をつなぐのは共有 ID であり、クロス DB 結合ではない

調査したシステムは、どれも関係ストアと数値ストアを、各テレメトリ行に載せた共有 ID でつないでいる。SkyWalking は relation 行の `entity_id` を系列 ID として使う。Dynatrace は `dt.smartscape.*` のノード ID をシグナルに載せる。DeepFlow は整数に符号化したタグをクエリ時に辞書で解決する（[DeepFlow SmartEncoding](https://deepflow.io/docs/features/auto-tagging/smart-encoding)）。リレーショナル DB と TSDB をまたいで結合するものはない。したがって shawk の要件は、**Postgres のエッジの同一性を Prometheus のラベルから一意に導けること**になる。service、host、port、「external」への畳み込みの正規化を、両方のストアで一字一句そろえなければならない。DeepFlow は、文字列タグが整数符号化に比べ CPU で 5〜10 倍のコストになると示し、量の多い系列には小さく安定した ID だけを載せる方針をとっている。この教訓からも、exe・version・ユニットの説明は Postgres に置き、系列には載せないのがよい。更新周期の違い（Postgres は 1〜5 分、TSDB は 15 秒）は避けられない。エッジが「存在するか」は Postgres を正、「どれだけ流れたか」は TSDB を正と明文化しておくべきだ。

### 廃止で失うもの：観測区間と活動の粒度

新設計は、記録期間（coverage）による「不明」判定と、現行の SQLite が持っていた分・時・日バケットの activity（既定で 2 日・90 日・3 年保持）を廃止する（[shawk design.md](https://github.com/yuuki/shawk/blob/main/docs/design.md)）。これは台帳の信頼性を下げる、最も見落としやすい後退だ。

理由の一つ目は、first_seen と last_seen の一区間では欠落区間を表せないことである。1 月に使われ、2 月は途絶え、3 月に戻った依存は区別できない。Dynatrace は時刻つきの動的エッジで、SkyWalking はバケットごとの行で、これを表している。理由の二つ目は、観測区間がなければ「使われていない」と「エージェントが止まっていた」を区別できないことだ。クライアント側のエージェントが 2 か月止まっていれば、そのエッジの last_seen は古くなり、未使用に見える。Prometheus のハートビートで補えるのは TSDB の保持期間内だけで、台帳の 90 日〜1 年には届かない。OTel のエンティティイベントは、報告間隔 `entity.report.interval` を持たせ、イベントが途絶えたらエンティティが消えたと推論させる（[OTel Entity Events](https://opentelemetry.io/docs/specs/otel/entities/entity-events/)）。NetObserv は「フローが観測されない」こと自体を `NetObservNoFlows` アラートにしている（[NetObserv HealthRules](https://github.com/netobserv/network-observability-operator/blob/main/docs/HealthRules.md)）。can-i-remove コマンドを廃止するのは構わない。しかし、その「不明」という誠実さはデータとして残す必要がある。

対策は小さく済む。一つは、エージェントの稼働区間を同じ least/greatest の upsert で記録する `agent_sessions(host_id, started_at, last_heartbeat, dropped_flows)` 表だ。もう一つは、エッジごと日ごとの活動表 `edge_days(edge_id, day, conns, bytes)` で、月単位のパーティションで 1 年保持する。1,000 ホストに各 200 の活発なエッジがあれば、年に約 7,300 万行になる。重ければ、月ごとに 1 行を持ち、活動日を 31 ビットのマスクで表す方法にすれば年に約 240 万行に縮む。この表は、後述する Node Graph の太さ、「定常的な依存の途絶」アラートのベースライン、稀な依存の周期の判定にもそのまま使える。

### 書き込み経路：冪等な upsert は堅いが、負荷と権限を詰める

least/greatest の upsert には見落とされがちな美点がある。DB 停止中にメモリで抱える状態が、時間ではなく**異なるエッジの数に比例する**ので、数時間止まっても膨らまない。ただし、エージェントが再起動すれば失われる。Coroot の node-agent は、push 先に届かないときのために WAL と既定 500MB のスプールを持つ（[Coroot flags.go](https://github.com/coroot/coroot-node-agent/blob/main/flags/flags.go)）。shawk にも小さなローカルスプールがあってよい。

負荷の面では、「変化した分だけ」といっても、活発なエッジは周期ごとに last_seen が変わるので毎回更新される。1,000 ホスト×200 エッジを 1〜5 分ごとに送れば、毎秒およそ 700〜3,300 行の更新になる。Postgres に不可能な量ではない。それでも、新規エッジは即座に書き、既存エッジの last_seen は前回値から 15〜60 分経ったときだけ更新するよう粗くすれば、桁で減らせる。権限の面では、全ホストが中央 DB の書き込み資格情報を持つことになる。ホスト単位のロールに行レベルセキュリティを掛けるか、upsert を SECURITY DEFINER 関数に閉じ込め、自ホストの行しか書けないようにすべきだ。エージェントの数だけ接続が張られるので、コネクションプーラも前提になる。読み取り側について、Grafana は「クエリの安全性を検証しない」と明記し、SELECT 権限だけのユーザを求めている。PostgreSQL 側では `statement_timeout` と `default_transaction_read_only` で暴走を抑えられる（[Grafana PostgreSQL configure](https://grafana.com/docs/grafana/latest/datasources/postgres/configure/)、[PostgreSQL runtime config](https://www.postgresql.org/docs/current/runtime-config-client.html)）。

## 両端の記録と NAT は、同じ依存を二重にも数え、途中で途切れさせもする

### 両側で記録するのは定石で、片側を正とする規約も定石である

同じ依存を両端で記録すること自体は珍しくない。Caretta は同じリンクをクライアント側ノードから `role="1"`、サーバ側ノードから `role="2"` で出す（[Caretta README](https://github.com/groundcover-com/caretta)）。SkyWalking はサーバ側とクライアント側の relation を別々に保存し、トポロジのクエリで両方を読む。DeepFlow は観測点を `c-p`（クライアントプロセス）と `s-p`（サーバプロセス）で区別する（[DeepFlow AutoMetrics](https://deepflow.io/docs/features/universal-map/auto-metrics)）。Istio のメトリクスも `reporter=source|destination` を持つ（[Istio metrics](https://istio.io/latest/docs/reference/config/metrics/)）。

差は、どちらを正とするかの規約にある。Kiali のグラフ生成の PromQL は `reporter="source"` を使う（[Kiali istio.go](https://github.com/kiali/kiali/blob/master/graph/telemetry/istio/istio.go)）。Datadog は「メトリクスは可能ならクライアント側で、なければサーバ側で計測する」（[Datadog Network Analytics](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/network_analytics/)）。opentelemetry-network の reducer は両端を一つのフローに突き合わせ、「二重計上を避けるため片側だけがメトリクスを更新する」（[flow_span.h](https://github.com/open-telemetry/opentelemetry-network/blob/main/reducer/matching/flow_span.h)）。shawk には今この規約がない。そのため `sum by (service, peer_service)` を全ホストで取ると、両端にエージェントがある依存では接続数もバイト数も倍になる。

規約はメトリクスごとに決めるのがよい。接続数、同時接続数、バイト数は両側で同じものを数えている。接続失敗は SYN が届かない以上クライアントにしか見えないので、クライアント側を正とする。一方、`total_retrans` は各ソケットが自分の送信で再送したセグメント数なので、クライアント側とサーバ側の再送は重複ではなく、向きの異なる二つの情報になる。RTT はクライアント側を正とすればよい。

サーバ側の記録には構造的な限界もある。エフェメラルポートを捨てているので、サーバ側の受信エッジからは、クライアントのホストまでしか特定できない。同じホストの複数のプロセスが同じサービスへつないでいれば、どのプロセスかは決められない。サービス対サービスの辺はクライアント側から、サーバ側はクライアントにエージェントがないときの代役、という Datadog と同じ規約が、shawk の情報の非対称性にも合っている。PromQL では `or` で書ける。以下は recording rule として同梱できる形だ。

```promql
# クライアント側を正とし、クライアント側の系列がない辺だけサーバ側で補う
  sum by (src, dst) (label_replace(label_replace(
      rate(shawk_connection_opened_total{shawk_role="client"}[5m]),
      "src", "$1", "service_name", "(.*)"), "dst", "$1", "service_peer_name", "(.*)"))
or
  sum by (src, dst) (label_replace(label_replace(
      rate(shawk_connection_opened_total{shawk_role="server"}[5m]),
      "dst", "$1", "service_name", "(.*)"), "src", "$1", "service_peer_name", "(.*)"))
```

Postgres の `dependencies` ビューも同じ規約で、論理的な依存 1 件を 1 行にまとめるべきだ。そのうえで `observed_by`（client / server / both）列を持たせる。片側にしか現れない依存は、それ自体がエージェント未導入か NAT を示す品質シグナルになる。

### 突き合わせの落とし穴は 0.0.0.0、VIP、ホスト内だけで有効なアドレス

SQL ビューでの突き合わせは、Coroot がサーバでクエリ時に行う結合を Postgres に移したものだ。Coroot はそのために、`0.0.0.0` で listen しているソケットのアドレスを、そのネットワーク名前空間に割り当てられた IP 群に置き換えている（[Coroot blog](https://coroot.com/blog/building-a-service-map-using-ebpf)）。shawk の listeners と host_addrs の結合にも、ワイルドカード listen を名前空間のアドレスへ展開する処理が要る。

`host_addrs` の「期間つきのアドレス所有」は、IP の再利用を時点つきで解決できる点で、OSS のどのツールが文書化しているものより明示的だ。ただし「1 つのアドレスにはある時点で 1 つの所有者」という前提だと、オンプレの現実と衝突する。keepalived/LVS の VIP は、ディレクタと実サーバのループバックに同時に存在する。コンテナのブリッジアドレスやループバックは、ホストごとに同じ範囲が再利用される。Weave Scope がエンドポイントの ID を（ホスト ID, 名前空間, アドレス, ポート）で組んだのは、アドレスが大域では一意でないからだ（[Weave Scope id.go](https://github.com/weaveworks/scope/blob/master/report/id.go)）。shawk の host_addrs にも、同時に複数の所有者を許すことと、「ホスト内のみ／経路上で有効」というスコープの区別が要る。

### NAT/LB：conntrack による解決は定石で、外部の LB は誰も解けない

NAT を明示的に解く OSS は Coroot だけだ。Coroot は netlink で conntrack を引き（Cilium の CT マップにも退避し）、各メトリクスに NAT 前の `destination` と NAT 後の `actual_destination` を両方持たせる（[Coroot container.go](https://github.com/coroot/coroot-node-agent/blob/main/containers/container.go)）。Datadog はもっと踏み込んでいる。conntrack のハッシュ挿入経路だけを eBPF でフックし、LRU マップに保持し、起動時には既存表を netlink でダンプする。netlink だけでは性能が「受け入れがたい」と判断した経緯がある（[datadog-agent PR #7500](https://github.com/DataDog/datadog-agent/pull/7500)）。その後 eBPF 版を既定にし、netlink 版を退路として残した（[PR #16010](https://github.com/DataDog/datadog-agent/pull/16010)）。大規模環境では 10 秒固定の netlink 初期化タイムアウトでエージェントが起動に失敗した事例もある（[issue #7781](https://github.com/DataDog/datadog-agent/issues/7781)）。opentelemetry-network は `__nf_conntrack_confirm` と `nf_ct_delete` をフックし、NAT されたエントリだけを記録していた（[render_bpf.c](https://github.com/open-telemetry/opentelemetry-network/blob/main/collector/kernel/bpf_src/render_bpf.c)）。どの製品にも限界がある。Datadog は既定で NAT 後の IP を表示し、NAT 前は要求時に出すが、「NAT ゲートウェイは解決しない」と明記している。Caretta は NAT を未解決の制約として文書化している（[Caretta blog](https://www.groundcover.com/blog/caretta)）。

オンプレでは、ケースを分けて考えると優先度が見える。HAProxy や nginx のようにコネクションを終端するフルプロキシは、NAT ではない。プロキシのホストにエージェントがあれば、「クライアント→プロキシ」と「プロキシ→バックエンド」の 2 本のエッジがプロキシのノードを経由してつながる。同一ホスト上の DNAT（podman/docker のポート公開、firewalld の転送）は、conntrack で解ける。LVS の DR 方式では、実サーバ側が本物のクライアント IP と VIP を見る。これは前述した多対多の host_addrs があれば突き合わせられる。ハードウェア LB の SNAT と NAT ゲートウェイは、どのツールも解いていない。Kiali が ServiceEntry で外部宛先に名前を付けるのと同じく（[Kiali FAQ](https://kiali.io/docs/faq/graph/)）、管理者が保守する VIP→プールの対応表を Postgres に置くしかない。サーバ側で見える相手が SNAT のアドレスなら、ホストに誤って帰属させず、「NAT 経由」と正直にラベル付けすべきだ。VIP の多い Rocky Linux の VM 群を主対象とするなら、conntrack による解決を「将来課題」から次期の範囲に引き上げる価値がある。鍵には、Coroot や Datadog と同じく NAT 前後の両アドレスを残すのがよい。

## ラベル設計が最大の逸脱点で、Prometheus 側は OBI 並みに絞るべきだ

### ペア×アドレスの次元は、先行ツールが既定で避けている

Prometheus の指針ははっきりしている。メトリクスのカーディナリティは 10 未満を目安とし、100 を超えうるなら別の解を探す（[Prometheus instrumentation](https://prometheus.io/docs/practices/instrumentation/)）。上限のない値はラベルにしない（[Prometheus naming](https://prometheus.io/docs/practices/naming/)）。shawk 案のラベル {host, service, direction, peer_addr, port, proto, peer_service} で概算してみる。1,000 ホスト×200 の組×8 本前後のメトリクスで、約 160 万系列になる。そのうえ peer_addr が、相手サービスのレプリカ IP の数だけ組を掛け算する。

先行ツールはこの次元を既定で避けている。OBI は送信元・宛先のアドレスとポートを既定で隠し、Beyla は外部アドレスを含めると「カーディナリティ爆発」になると警告する（[OBI metrics](https://opentelemetry.io/docs/zero-code/obi/metrics/)、[Beyla network](https://grafana.com/docs/beyla/latest/network/)）。opentelemetry-network は最も細かい `id-id` 系列を既定でオフにした（[reducer.md](https://github.com/open-telemetry/opentelemetry-network/blob/main/docs/reducer.md)）。Retina は送信元×宛先の「remote context」を「上限なし」と呼び、規模向けには片側だけの「local context」を勧める（[Retina modes](https://retina.sh/docs/Metrics/modes/)）。NetObserv は Src と Dst の名前を両方使うと「カーディナリティの二乗」になると注記している（[NetObserv Metrics.md](https://github.com/netobserv/network-observability-operator/blob/main/docs/Metrics.md)）。例外は Coroot で、コンテナごとに ip:port を持ちながら実用になっている。それは、10 分のアイドル GC、エフェメラルポートの除外、コンテナあたり FQDN 50 件で `~other` に畳む上限を組み合わせているからだ（[Coroot flags.go](https://github.com/coroot/coroot-node-agent/blob/main/flags/flags.go)）。逆に Caretta は系列を一度も消さず、エージェントの再起動まで溜め続ける。これは反面教師である（[caretta.go](https://github.com/groundcover-com/caretta/blob/main/pkg/caretta/caretta.go)）。

shawk は正確なアドレスを Postgres に持っている。だから TSDB にアドレスを置く理由は他のツールより弱い。推奨は四点だ。第一に、peer_addr を既定のラベルから外し、相手は `service.peer.name` 一本にする。値は、解決できればサービス名、できなければ名前付き CIDR、それもなければ external の順で決める。第二に、「external」の一括りを、OBI の名前付き CIDR（`0.0.0.0/0` を受け皿にできる）や NetObserv の `subnetLabels` のような設定可能な範囲名に一般化する（[OBI network config](https://opentelemetry.io/docs/zero-code/obi/network/config/)、[FLP api.md](https://github.com/netobserv/flowlogs-pipeline/blob/main/docs/api.md)）。第三に、Coroot の FQDN 上限に倣い、ホスト・サービスあたりの相手の数に上限を設けて `~other` に畳む。第四に、「しばらく活動のないエッジは送らない」の「しばらく」を数値で決める。相場は Coroot の 10 分、Tempo と Collector コネクタの 15 分、flowlogs-pipeline の 2 分である（[connector.go](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/connector/servicegraphconnector/connector.go)）。削減はエージェント内で行い、Collector の `transform` の `limit()` や `delete_key` は安全網にとどめるのがよい（[transformprocessor](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/transformprocessor)）。累積カウンタを Collector で再集約すると、リセットや二重計上を招きやすいからだ。

### エージェント側で peer_service を付けるのは定石だが、値の揺れを抑える必要がある

発行時に相手の身元を解決する方式は、Caretta、OBI、Istio と同じだ。Coroot のようにクエリ時に解決する方式と比べて、劣っているわけではない。DeepFlow は取り込み時にタグを注入する。そのため各行は書き込み時点で正しかったリソースを保持し、後から IP が再利用されても過去のデータは汚れない（[DeepFlow SmartEncoding](https://deepflow.io/docs/features/auto-tagging/smart-encoding)）。

問題は正しさではなく、値の揺れにある。新しいサーバの listener は、そのエージェントが同期するまで（最大 5 分）Postgres に現れない。その間、クライアント側の系列は「未解決」で始まり、解決後に別の系列へ切り替わる。DB に届かない間もラベルが揺れる。対策として、最後に得た対応表をキャッシュし、未解決のときは常に同じ値を使い、新規フローの初回送出を一度の解決試行の後まで遅らせる。そのうえで、TSDB のラベルは「発行時点の最善の推定」であり、帰属の正は Postgres だと文書化すればよい。受信側の系列については、前節のとおり相手をホスト粒度にとどめるのが一貫する。

### OTel と Prometheus の名前に寄せる

接続単位の TCP/UDP フローに安定した semconv メトリクスはない。最も近い `system.network.connection.count` も Development 段階だ（[OTel system metrics](https://opentelemetry.io/docs/specs/semconv/system/system-metrics/)）。そのため、OBI のように独自の名前空間（`shawk.*`）を使い、属性だけ semconv に寄せるのが先例に沿う。名前の対応は下表のとおりにする。`network.io.direction` は「ステートフルな接続の論理的な向き」ではなくインタフェースの送受信を表すので、クライアント/サーバの役割に使ってはならない（[OTel network attributes](https://opentelemetry.io/docs/specs/semconv/registry/attributes/network/)）。相手サービスの概念は `peer.service` ではなく `service.peer.name`（Development）である（[OTel service attributes](https://opentelemetry.io/docs/specs/semconv/registry/attributes/service/)）。

| 現案のラベル | 推奨する OTel 属性 | Prometheus 上の名前 | 理由 |
|---|---|---|---|
| host | resource の `host.name`（または `host.id`）を昇格する | `host_name` | 既定では resource 属性はラベルにならず、datapoint の `host` と概念が衝突する |
| service | `service.name`（datapoint） | `service_name` | OBI と同じ。resource の `service.name` はエージェント自身を表し `job` になる |
| peer_service | `service.peer.name` | `service_peer_name` | semconv の名前 |
| port | `server.port` | `server_port` | 向きに関係なく常にサービスポートなので、`server.*` が意味に合う |
| proto | `network.transport` | `network_transport` | Stable |
| direction | `shawk.role`（client/server） | `shawk_role` | `network.io.direction` の誤用を避ける |
| peer_addr | `network.peer.address`（任意で有効化） | `network_peer_address` | Stable。既定では出さない |

Prometheus 側の設定にも決めておくべき点がある。Prometheus 3.x のネイティブ OTLP 受信口（`--web.enable-otlp-receiver`）は、既定では resource 属性を一つもラベルにしない。`service.name` は `job`、`service.instance.id` は `instance` になり、その他は `target_info` にだけ残る（[Prometheus OTel guide](https://prometheus.io/docs/guides/opentelemetry/)）。そのため `host.name` は `promote_resource_attributes` で明示的に昇格させる必要がある。既定の変換規則では、カウンタに `_total`、単位 By に `_bytes` が付く。3.14 では、正規化後に名前が衝突すると警告メトリクスが出るようになった（[Prometheus CHANGELOG](https://github.com/prometheus/prometheus/blob/main/CHANGELOG.md)）。delta temporality は 2 方式とも実験的なので、設計どおり累積を貫くのが正しい（[Prometheus feature flags](https://prometheus.io/docs/prometheus/latest/feature_flags/)）。Collector の `prometheusremotewrite` exporter は delta の和を黙って捨てる（[prometheusremotewrite README](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/prometheusremotewriteexporter)）。ガイドが勧める 30 分の out-of-order 窓も有効にしておく。RTT は、OBI がヒストグラム（`obi_stat_tcp_rtt_seconds`）で出している。ただし固定バケットのヒストグラムは系列数をバケット数倍にする。既定は和と回数のまま（Datadog に倣ってジッタを足してもよい）にし、分位が要るならネイティブヒストグラムを任意で有効にする、という順序が安全だ。

## Grafana 連携とアラートは成立するが、Postgres アラートの形式制約に合わせて組む

### Node Graph：SQL で直接供給する方式は Caretta より筋が良く、200 ノードの壁がある

Node Graph パネルは、refId またはフレーム名が `nodes`/`edges` のフレームか、`id` フィールドを持つフレームを認識する。エッジは `id`/`source`/`target` が必須で、`mainstat`・`thickness`・`color` などは任意だ。ノードは `id` が必須である。`arc__*` の値は合計 1 にする必要があり、`highlighted` は 10.5 で非推奨になって `color` に置き換わった（[Grafana Node graph](https://grafana.com/docs/grafana/latest/panels-visualizations/visualizations/node-graph/)）。したがって、Postgres パネルに refId `nodes` と `edges` の 2 クエリを置き、小文字の別名で列を返せば、変換なしで描ける。コミュニティには、SQL ソースでフレーム名と列の別名の大小文字に悩んだ報告がある（[Grafana community](https://community.grafana.com/t/grafana-node-graph-with-sql-tables/61919)）。小文字にそろえておけば安全だ。

この方式は、Caretta が「PromQL の魔術」と自嘲した方式よりはっきり筋が良い。Caretta は Node Graph のためだけにハッシュ値の `link_id`/`client_id`/`server_id` ラベルを発行し、`label_replace` で無理やり形を合わせていた（[Caretta dashboard.json](https://github.com/groundcover-com/caretta/blob/main/chart/dashboard.json)）。shawk ならその合成 ID を TSDB に持ち込まずに済む。

一方で、規模の壁がある。既定で表示されるのは 200 ノードまでで、層状レイアウトは 500 ノードを超えると遅くなる。実際に「Computing layout」で固まった報告もある（[Grafana community](https://community.grafana.com/t/node-graph-issue-nodes-are-hidden-for-performance-reasons/147404)）。N ホップに限る再帰 SQL という設計はその意味で正しい。ただし依存グラフは循環するので、PostgreSQL の `CYCLE` 句と深さ上限を必ず入れる。公式文書は、暴走を `LIMIT` で止める手口を本番では勧めていない（[PostgreSQL WITH](https://www.postgresql.org/docs/current/queries-with.html)）。そのうえで、読み取りロールの `statement_timeout` で上限を掛ける。フリート全体を一枚にしたい要望には、Datadog のネットワークマップが自動で第二のグルーピングタグを加えてまとめるように（[Datadog Network Map](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/network_map/)）、ノードの粒度をホスト → サービス → チームと切り替えるテンプレート変数で応えるのがよい。

エッジの太さに TSDB のレートを使うには、データソースをまたぐ必要がある。SQL Expressions は既定で有効で、データソースをまたいで JOIN できる。ただし入力は 10 万セル、時間は 10 秒が上限で、Prometheus の対応は「部分的」にとどまる（[SQL expressions](https://grafana.com/docs/grafana/latest/panels-visualizations/query-transform-data/sql-expressions/)）。前述の `edge_days` があれば、太さも Postgres だけで描ける。Hubble UI（ライブ）と Timescape（履歴）の分担に倣い、Caretta 式に Prometheus だけで組む「ライブ」の Node Graph を補助として並べる手もある。これは系列を増やさずに作れる。

### SQL アラート：「1 行 1 インスタンス」は時系列形式で組み、空の結果を Normal にする

設計案で最も注意が要るのはここだ。Grafana の PostgreSQL 向け文書は、「アラートルールの条件には時系列形式のクエリしか使えない」と明記している。`time` 列と数値列が必須で、文字列列がラベルになり、ラベル値の組ごとに 1 つのアラートインスタンスができる。`$__timeGroup` の fill はアラート評価時には適用されず、ダッシュボード変数も使えない（[Grafana PostgreSQL alerting](https://grafana.com/docs/grafana/latest/datasources/postgres/alerting/)）。他方、汎用の表形式アラートの文書は「各行を別のインスタンスとして扱う」と書き、SQL の例まで載せている（[Grafana table data alerting](https://grafana.com/docs/grafana/latest/alerting/best-practices/table-data/)）。文書が食い違っているので、対象の Grafana バージョンで実際に試すまでは時系列形式に寄せるのが安全だ。数値の port はラベルにしたければ文字列にキャストする。

```sql
SELECT max(first_seen) AS time, src_service, dst_service, port::text AS port, 1::int AS value
FROM dependency_changes WHERE $__timeFilter(first_seen)
GROUP BY 2, 3, 4 ORDER BY 1
```

評価の挙動も設計に効く。結果が 0 行のときは No Data になり、既定では独立した `DatasourceNoData` インスタンスが作られる。新規依存のない静かな時間帯に鳴らさないよう、No Data は Normal にする（[No Data and Error states](https://grafana.com/docs/grafana/latest/alerting/fundamentals/alert-rule-evaluation/nodata-and-error-states/)）。新規依存が窓から外れると、系列が 2 回連続で欠けた時点で `MissingSeries` として自動解決し、解決通知が出る（[Stale alert instances](https://grafana.com/docs/grafana/latest/alerting/fundamentals/alert-rule-evaluation/stale-alert-instances/)）。「依存や listener の消滅」をこの自動解決で表してはならない。`last_seen` がある窓に入った行として、明示的に選ぶべきだ。デプロイ直後には新規依存がまとまって出るので、通知ポリシーのグルーピング（既定は alertname と folder、待機 30 秒、間隔 5 分、再通知 4 時間）に service を加える（[Group alert notifications](https://grafana.com/docs/grafana/latest/alerting/fundamentals/notifications/group-alert-notifications/)）。

ノイズの扱いにも先例がある。ServiceNow が、トラフィック由来の発見を初期の地図作り以外では止めるよう勧めている（[ServiceNow](https://www.servicenow.com/docs/bundle/washingtondc-it-operations-management/page/product/service-mapping/concept/traffic-based-discovery.html)）。これは、トラフィック由来のエッジが雑音を含むことの裏返しだ。特に「外部への新しい通信」は、CDN やクラウド API の IP が入れ替わるだけで鳴る。生の IP ではなく、名前付き CIDR、Datadog の `domain` タグのような DNS 由来の名前、あるいは Coroot の `ip_to_fqdn` のような単位で「新しさ」を判定すべきだ（[Datadog Network Analytics](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/network_analytics/)、[Coroot docs](https://docs.coroot.com/metrics/node-agent)）。なお、新規依存を第一級のイベントとして文書化している製品は、調査範囲では見つからなかった。Datadog CNM も「予期しない依存の特定」を用途に挙げるだけだ（[Datadog CNM](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring)）。うまく作れば明確な差別化点になる。

### 注釈とデータリンクはそのまま使えるが、version の履歴が要る

Postgres の注釈クエリは `time` を返し、任意で `timeend`・`text`・`tags` を返す。`timeend` を返すと縦線ではなく網掛けの区間になる（[Grafana PostgreSQL annotations](https://grafana.com/docs/grafana/latest/datasources/postgres/annotations/)）。注釈はダッシュボード単位のクエリでデータソースを個別に選べるので、Mixed データソースを使わずに Prometheus のパネルへ重ねられる。エッジの寿命を区間注釈で見せることもできる。ただし「service.version の切り替わり」を出すには、processes 表がバージョンをその場で上書きしていては切り替え時刻が残らない。（プロセス, version, first_seen, last_seen）の履歴表が要る。

Postgres のパネルから Prometheus のパネルへの遷移は、データリンクで書く。`${__data.fields.service}` と `${__url_time_range}`、`var-<変数名>=` を使えばよい（[Configure data links](https://grafana.com/docs/grafana/latest/panels-visualizations/configure-data-links/)）。Correlations はリンクを Explore の Logs と Table にしか出さないので、ダッシュボード用途には向かない（[Correlations](https://grafana.com/docs/grafana/latest/administration/correlations/)）。

### PromQL アラートは「意見つきのテンプレート」として同梱する

ルールを同梱する方針は、NetObserv と Coroot の先例に合う。NetObserv はヘルスルールを PrometheusRule のテンプレートとして持つ。各ルールは critical/warning/info のしきい値と、ノードごとなどのグルーピングを変種として持ち、自己監視の `NetObservNoFlows` と runbook も付く。前日比（`offset 1d`）で +100% を超えたら発報する流入急増の例もある（[NetObserv HealthRules](https://github.com/netobserv/network-observability-operator/blob/main/docs/HealthRules.md)）。Coroot は、ルールではなくアプリ文脈での「検査」としてしきい値を持ち、アプリやプロジェクトごとに上書きできる（[Coroot inspections](https://docs.coroot.com/inspections/overview)）。shawk の失敗率・再送率・RTT 悪化も、`offset 1d` との比較と重大度の段階を備えたテンプレートにするとよい。

「定常的な依存の途絶」には、何を「定常」とみなすかのベースラインが要る。Tempo は低トラフィックの辺のために、観測中は 1 を保つだけの `traces_service_graph_connection_info` を加え、`last_over_time(...[1h]) > 0` で見るよう勧めている（[Tempo service graphs](https://grafana.com/docs/tempo/latest/metrics-from-traces/service_graphs/)）。shawk の同時接続数ゲージは、長寿命の接続についてこの役を果たす。月次バッチのような依存は、`edge_days` の周期（直近 M 日のうち N 日以上活動したか）で判定しないと誤報になる。

エージェント停止の検知にも注意が要る。OTLP の push には scrape の `up` がない。ホストごとのハートビート系列の欠落を、`absent_over_time` か過去との差分で検出する必要がある。加えて、TSDB の保持期間を超えて効く `agent_sessions.last_heartbeat` への SQL アラートを併設すべきだ。

## VM/オンプレの OSS は空白になりつつあり、立ち位置は有利だが運用面の詰めが要る

プロジェクトの状況は、shawk の立ち位置を後押ししている。opentelemetry-network は、担当する SIG がなく、セキュリティ更新も途絶えたとして、2026 年 10 月 6〜7 日にアーカイブされた。後継の受け皿には OBI が挙げられている（[open-telemetry/community #3693](https://github.com/open-telemetry/community/issues/3693)）。Caretta は最終 push が 2025-03-17 で、chart は 0.0.1 のまま止まっている（[ecosyste.ms caretta](https://repos.ecosyste.ms/api/v1/hosts/GitHub/repositories/groundcover-com%2Fcaretta)）。Weave Scope は 2023-06-13 に非推奨となった（[weaveworks/scope](https://github.com/weaveworks/scope)）。Cilium の VM 向け機能（external workloads）は 1.18 前後で非推奨または削除とされているが、資料間で食い違いがある（[cilium-cli v0.17.0](https://newreleases.io/project/github/cilium/cilium-cli/release/v0.17.0)）。Retina と NetObserv は Kubernetes 前提だ（[microsoft/retina](https://github.com/microsoft/retina)、[NetObserv Architecture](https://github.com/netobserv/network-observability-operator/blob/main/docs/Architecture.md)）。フロー系ツールの中でホストを第一級に扱うのは商用の Datadog（Linux と Windows）だけで、Rocky Linux は対応ディストリビューションに明記されていない（[Datadog CNM setup](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/setup/)）。Azure Migrate のエージェント型依存分析（クラシック表示）も 2026 年末に廃止予定である（[Azure Migrate](https://learn.microsoft.com/en-us/azure/migrate/concepts-dependency-visualization)）。

最も手強い OSS の競合は Coroot だ。node-agent は 2026-09-16 にも push されており活発で（[ecosyste.ms coroot-node-agent](https://repos.ecosyste.ms/api/v1/hosts/GitHub/repositories/coroot%2Fcoroot-node-agent)）、systemd ユニットを扱えるので VM にも効く。shawk が Coroot と差別化できるのは、長期の関係台帳、新規依存のイベント、そして Grafana にネイティブに載る点である。Coroot は独自 UI を持ち、ClickHouse にも対応し、Prometheus の保持を数時間に縮められる独自キャッシュを持つ（[Coroot Prometheus config](https://docs.coroot.com/configuration/prometheus)）。逆に言えば、ライブのサービスマップの出来栄えで Coroot と競う設計判断は、shawk の利点を生かさない。

OBI は CNCF に寄贈された Beyla の後継で、v0 の間は破壊的変更があると明言しつつ、2026 年の旗艦目標に 1.0 を掲げている（[OBI README](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation)、[OBI 2026 goals](https://opentelemetry.io/blog/2026/obi-goals/)）。その StatsO11y の `obi_stat_tcp_*`（RTT、失敗接続、再送、I/O）は、shawk の数値と重なる。OBI が非 Kubernetes ホストへ広がったときに相互運用できるよう、属性名を OBI と semconv に寄せておく価値はここにもある。

OTel Entities は依然として Development 段階だ。エンティティイベントの仕様は v1.58.0（2026-06-22）で入ったとブログは述べるが、仕様ページとブログで属性名が食い違っている（[OTel blog](https://opentelemetry.io/blog/2026/consuming-opentelemetry-entity-events/)、[OTel Entity Events](https://opentelemetry.io/docs/specs/otel/entities/entity-events/)）。これを台帳の主経路にするのは時期尚早である。それでも shawk の upsert は、ブログが勧める「イベント源の追記と連続区間の圧縮」とほぼ同型だ。身元を不変の識別属性（ホスト ID、ユニット）に、IP・comm・version を可変の説明属性に分けておけば、将来エンティティイベントとして書き出す道は開いたままになる。ブログは、PID は再利用されるのでプロセスを `process.pid` と `process.creation.time` の組で識別するよう勧めている。ホスト名も変わりうるので、識別子には安定したホスト ID を使い、名前は説明属性にするのが筋だ。

運用面では、先例が三つの宿題を示している。一つ目は SELinux だ。opentelemetry-network はコンテナで動かす場合に `bpf` 権限を許すカスタムポリシーを必要とし、Datadog は CentOS 向け RPM にポリシーモジュールを同梱している（[kernel-collector.md](https://github.com/open-telemetry/opentelemetry-network/blob/main/docs/kernel-collector.md)、[Datadog CNM setup](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/setup/)）。Rocky 9 を主対象とする以上、enforcing での動作確認は必須だ。二つ目は検証環境である。shawk の設計文書自身が、プログラムは Ubuntu カーネルで実行し、Rocky 9.6 の BTF には静的に照合しただけで、実際の Rocky カーネルではまだ動かしていないと認めている（[shawk design.md](https://github.com/yuuki/shawk/blob/main/docs/design.md)）。主対象の実機 CI は、新設計のどの変更よりも先に要る。三つ目は CO-RE の徹底で、これは既に満たしている。opentelemetry-network はノード上でのコンパイルを捨てて CO-RE へ移ることを目標にし、Datadog も 7.60 で事前ビルド版を非推奨にした（[datadog-agent 7.60.0](https://github.com/DataDog/datadog-agent/releases/tag/7.60.0)）。

将来アイディアのうち、Tempo の service graph との突き合わせは筋が良い。service graph のメトリクスは `client`/`server` ラベルを持ち、未計装の相手を `peer.service` などから仮想ノードとして描く。Collector のコネクタは今も alpha で、名前も `service_graph` に改められた（[servicegraphconnector README](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/connector/servicegraphconnector)）。突き合わせが成り立つかは、shawk の service とアプリの `service.name` が一致するかにかかっている。shawk は `/proc/PID/environ` の `OTEL_SERVICE_NAME` を読むので、環境変数で名前を与えるアプリとは自然に一致する。コードや設定ファイルで名前を与えるアプリとは一致しないので、別名表が要る。Coroot 式の NAT 解決は、前述のとおり「将来」から外すべきだ。

## 優先度つきの推奨：設計変更点

P0 は設計を固める前に決めるべきこと、P1 は初版から次版までに入れるべきこと、P2 は差別化を深める改善である。

| 優先度 | 設計変更 | 根拠となる先例・制約 |
|---|---|---|
| P0 | Prometheus のラベルから peer_addr を外し、相手は `service.peer.name`（サービス名 → 名前付き CIDR → external の順で解決）に一本化する。アドレスは Postgres にのみ置き、TSDB では任意で有効化する | OBI はアドレスを既定で隠し、opentelemetry-network は `id-id` を既定でオフにする。Prometheus の 10/100 の指針 |
| P0 | アイドル系列の TTL を 10〜15 分と明記し、ホスト・サービスあたりの相手数に上限を設けて `~other` に畳む | Coroot は 10 分の GC と FQDN 50 件の上限、Tempo とコネクタは 15 分。Caretta は消さない反面教師 |
| P0 | 二重計上の規約を定める。接続数・失敗・バイト数・RTT はクライアント側を正とし、サーバ側はクライアント側がない辺の代役にする。再送は向き別に扱う。PromQL の `or` による recording rule と、`dependencies` ビューの `observed_by` 列で実装する | Kiali の `reporter="source"`、Datadog の client 優先、opentelemetry-network の片側更新 |
| P0 | `agent_sessions`（稼働区間とドロップ数）を Postgres に残し、「未使用」と「未観測」を区別できるようにする | OTel の `entity.report.interval`、NetObserv の `NetObservNoFlows`。現行の can-i-remove の「不明」判定 |
| P0 | Postgres アラートを時系列形式（`time`＋文字列ラベル＋数値 1 列）で設計し、No Data は Normal にし、消滅は明示的な行で表す。対象の Grafana バージョンで表形式の可否を検証する | Grafana の PostgreSQL アラート文書と表形式アラート文書が食い違っている |
| P1 | `edge_days`（または月×日のビットマスク）で日次の活動を 1 年保持し、欠落区間・稀な依存の周期・Node Graph の太さ・途絶アラートのベースラインに使う | Dynatrace の時刻つき動的エッジ、SkyWalking のバケット行。現行の activity の 3 年保持 |
| P1 | host_addrs を多対多かつスコープつき（ホスト内のみ／経路上で有効）にし、0.0.0.0 の listener を名前空間のアドレスへ展開する | Coroot のワイルドカード置換、Weave Scope の（ホスト, 名前空間, アドレス, ポート）ID |
| P1 | conntrack による NAT 解決を次版の範囲に入れる。`__nf_conntrack_confirm`/`nf_ct_delete` を LRU で追い、起動時に netlink でダンプ（タイムアウトは設定可能）し、NAT 前後の両アドレスを保持する。外部 LB には手動の VIP→プール対応表を用意する | Coroot、Datadog の PR #7500・#16010・issue #7781、opentelemetry-network |
| P1 | Postgres の書き込み経路を硬くする。last_seen の更新を 15〜60 分に粗くし、ホスト単位のロールと RLS または SECURITY DEFINER 関数で自ホストの行に限り、コネクションプーラを置き、小さなローカルスプールを持つ。Grafana には `statement_timeout` つきの読み取り専用ロールを使う | Coroot の WAL・スプール。Grafana は SQL の安全性を検証しない |
| P1 | OTel/Prometheus の命名を寄せる（上表）。`host.name` を昇格し、累積を維持し、out-of-order 窓を 30 分にする | OTel の network・service 属性、Prometheus の OTLP ガイド、OBI の先例 |
| P1 | process の version 履歴表を設け、注釈を正しく出す。再帰 SQL には `CYCLE` 句と深さ上限を入れる | Grafana の注釈の仕様、PostgreSQL の WITH の文書 |
| P1 | Rocky 9 の実カーネル（SELinux enforcing）で CI を回す | shawk の設計文書自身の記述。opentelemetry-network と Datadog の SELinux 対応 |
| P2 | 接続失敗に `reason`（refused/timeout/reset）を付け、RTT にジッタを足す | Datadog の失敗の分類、OBI の `reason` ラベル |
| P2 | UDP の fentry から kprobe への退路を用意し、フロー表が満杯のときは捨てずにリングバッファで退避させる | Datadog の PR #59165、NetObserv v2 |
| P2 | 外部宛先を DNS 名や名前付き CIDR で表し、「新しい外部通信」アラートを IP 単位でなくグループ単位にする | Datadog の `domain` タグ、Coroot の `ip_to_fqdn`、NetObserv の `subnetLabels` |
| P2 | ノード粒度（ホスト/サービス/チーム）を切り替える変数と、Prometheus だけで組むライブの Node Graph を補助として加える | Node Graph の 200 ノードの既定、Datadog の自動クラスタリング、Caretta |
| P2 | Tempo の service graph との突き合わせのため、service の別名表を設ける。OTel エンティティイベントの書き出しは仕様が Stable になってから検討する | コネクタは alpha、Entities は Development |

## 結論

このレビューで見えてきたのは、shawk の新設計の本当の製品が「もう一つのサービスマップ」ではない、ということだ。それは「長い記憶を持ち、変化を知らせる依存台帳を、Grafana に載せたもの」である。ライブのマップは Coroot、Hubble、Kiali、OBI がすでに埋めている。一方、数か月単位の関係履歴と新規依存のイベントは、OSS では空いたままだ。したがって設計判断の良し悪しは、台帳の信頼性を守るかどうかで測るべきである。coverage と日次活動の廃止、NAT の先送り、アドレスのスコープを持たない host_addrs は、いずれも小さな簡略化に見える。しかし三つとも、「90 日誰も使っていない」という台帳の中核の主張を静かに偽にしうる。

逆に Prometheus 側は、あえて平凡にしてよい。TSDB は shawk が OBI や Coroot と同じ土俵に立つ場所で、そこで独自のラベル設計を貫いても得るものは少ない。失うもの（系列数、名前の非互換）は大きい。アドレスと身元の詳細は Postgres に寄せ、TSDB は semconv に沿ったサービス粒度の数値に徹する。この「台帳は独自に、数値は凡庸に」という非対称な分担こそが、二つの店を持つ設計を正当化する最も強い理由になる。
