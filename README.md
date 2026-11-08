# F4KEENV

多数のAPIサービスの認証情報を模した合成シークレット・データセット。
現在の生成カタログは **115サービス・191形式**です。元の16サービス・25形式から拡張しました。
追加166形式は固定した公開検出ルールとGoソースのサービス分類に由来し、独立したGo正規表現でも生成例を検証しています。
サービス数はトークン種別数と分け、汎用JWT・秘密鍵・ハッシュ等をサービスとして数えません。
これは「115サービスの現行公式発行方式を確認済み」という意味ではありません。
既存の公開10,000件と最初のベンチマークは、旧16サービス・25形式の凍結スナップショットです。
既存の121個の環境設定ファイルも保持しています。

## 調査台帳の収集

収集CLIはPython **3.11以上**を使用します。既存の合成キー生成器は従来どおり利用できます。
JSON Schema検証用に `jsonschema` を使用します。Windowsで複数のPythonが入っている場合は
`py -3.12` などで通常のCPythonを選択してください。

```sh
python -m venv .venv
# Windows: .venv\Scripts\activate / macOS・Linux: source .venv/bin/activate
python -m pip install -r requirements-research.txt

# 全ディレクトリ候補を取り込み、独立したproviderを優先して20個のOpenAPIを取得
python -m f4keenv collect --spec-limit 20

# キャッシュ再利用。サービスID・出典IDが同じなら件数は増えません
python -m f4keenv collect --spec-limit 20

# 取得範囲を拡大。API keyの発行やサービスへの認証は行いません
python -m f4keenv collect --spec-limit 1000

python -m f4keenv validate
python -m f4keenv export

# 共有用の抽出メタデータを新規ディレクトリへ保存（本文キャッシュは含めません）
python -m f4keenv export --output registry-new

# 手元のOpenAPI JSONも解析可能（外部$refは自動取得しません）
python -m f4keenv import-openapi openapi.json --domain example.com --product api --source-url https://example.com/openapi.json
```

取得結果はGit除外の `work/research/` に保存します。`--workspace PATH` はサブコマンドの前に指定します。
HTTPタイムアウト30秒、レスポンス上限32MiB、ホストごとの待機、robots.txt確認、
取得日時とSHA-256付きキャッシュを使用します。ネットワーク取得先はソース実装内の許可ホストに限定します。
再取得は `collect --refresh`。失敗したソース・仕様は `collection-report.json` に記録して終了コード1を返します。
成功した取り込み結果は残るため、失敗を隠さず再開できます。
`--workers 4`（既定値）で取得を並列化しますが、ホスト全体で毎秒最大4リクエストに制限します。
バージョン名に空白が含まれる取得URLはエンコードし、SQLite更新はメインスレッドのトランザクションで行います。

台帳はSQLiteのトランザクションで保存し、次のJSONLを改変しないスナップショットとして書き出します。
`latest.json` が最新スナップショットを示し、各ファイルの件数とSHA-256は `manifest.json` に記録します。

| ファイル | 内容 |
|---|---|
| `providers.jsonl` | ドメインと製品名から正規化したサービス候補、出典、認証観測状況 |
| `credentials.jsonl` | 認証の配置・方式、形式、発行方式を分けた記録 |
| `evidence.jsonl` | URL、取得日時、本文ハッシュ、参照コミット、ライセンス確認状態 |
| `detectors.jsonl` | Gitleaks規則、GitHub公式のsupported patterns、TruffleHog・detect-secretsのソース索引 |
| `tasks.jsonl` | 候補ごとの具体・抽象・関連検索クエリと未調査状態 |

APIs.guruはpreferredバージョンを取り込み、元の `x-origin` URLも保存します。
Gitleaksは既存カタログと同じコミットに固定し、regexだけでなくentropy・keywords・allowlistも保存します。
TruffleHogとdetect-secretsはソースの発見索引です。ソースユニット数を実装済み検出ルール数やサービス数と混同しません。
GitHubの公式対応表はページに埋め込まれた公開JSON全体から取り込み、表示先頭ページだけの取得を避けます。
正規表現自体は非公開のため取得しません。ページ構造が変わった場合は部分取り込みをせず失敗として記録します。
生成カタログ191形式も台帳に取り込みますが、識別の根拠が異なるため `catalog:` 名前空間の未検証候補とします。
ドメインの所有関係、買収、製品間の統合を推測して自動マージする処理は含めません。

OpenAPI解析はSwagger 2.0 / OpenAPI 3.xのJSONに対応します。ルートと操作ごとのsecurity、
OR/ANDの要件、匿名アクセス、ローカルJSON Pointer参照、OAuth flow、OIDC、mTLS、apiKeyの配置を保持します。
外部参照・循環参照・未定義schemeは問題として残します。YAMLや複数ファイル仕様の自動解決には未対応です。
`bearerFormat` はヒントとして保持し、キーの文字列表現や内部発行アルゴリズムへ変換しません。

**候補サービス数・認証方式を観測したサービス数・公式確認済みサービス数を別に集計します。**
集約ディレクトリと検出器からの情報は公式確認に昇格させません。不明な形式・発行方式は `unknown` のままです。
10,000件の合成キーを10,000サービスの調査完了とは数えません。

収集コマンドは既存の公開合成データを変更・再生成・再公開しません。

## 調査キュー・監査・生成・検出器比較

```sh
# 新規性・カテゴリの不足・不確実性・検出器関連性・根拠の強さで優先順位を更新
python -m f4keenv schedule --limit 100 --output work/research-next.jsonl

# 出典種別・形式の確度・confidenceで層化した人手レビュー対象
python -m f4keenv audit-sample --per-stratum 5 --output work/audit-sample.jsonl

# 出典を持つ現在の191形式から50正例＋50負例ずつ生成。高忠実度データはGit除外領域へ
python -m f4keenv generate-corpus --output benchmark-local/evaluation-v1
python -m f4keenv validate-corpus benchmark-local/evaluation-v1

# 値を一切生成しない公開用テンプレート。形式が不明なOpenAPI認証情報も明示して出力
python -m f4keenv public-templates --output corpus-public-new

# Windows x64: 公式リリースの固定バージョンを取得して公開checksumと照合
python scripts/setup_benchmark_tools.py
python -m pip install -r requirements-benchmark.txt

# PowerShell用。コマンドは1行で実行
python -m f4keenv benchmark benchmark-local/evaluation-v1 --output benchmark-local/results-v1 --gitleaks work/tools/gitleaks/gitleaks.exe --trufflehog work/tools/trufflehog/trufflehog.exe --detect-secrets .venv/Scripts/detect-secrets.exe
```

調査キューは実行可能な具体・抽象・関連の検索語と既知の原典URLを持ちます。
`schedule` 自体は検索サービスへ送信せず、未調査タスクをエージェントや人に渡すために書き出します。
ドキュメントの再帰検索の自動実行と、人手による根拠確認は別途必要です。

ローカルcorpusは.env・JSON・YAML・Pythonの4文脈で生成し、正例・形式を1文字壊したnear-miss・
UUID/commit hashの自然な負例を区別します。固定seedが既定で、`--seed NAME` または `--os-random` で切り替えます。
値にダミー用markerを入れず、manifestに `synthetic`・`never_issued`・`public_release:false`・
出典ID・generator version・seed ID・ファイルハッシュを必須で持たせます。
公開形式が不明なサービスのキーを捏造しません。生成対象からの除外件数もmanifestに記録します。
近似形式のHypixelは正解ラベルを `null` にして採点から除外します。

Gitleaksはローカルの実バイナリーを実行します。TruffleHogは `--no-verification --no-update`、
detect-secretsは `--no-verify` を固定し、外部のcredential検証を止めます。
各検出器のversion・コマンド・壁時計時間・MB/s・TP/FP/FN/TN・precision/recall/FPRを保存し、
provider・credential type・variant・context・format別にも集計します。失敗した検出器を全件FNとして採点しません。
CPU時間と最大メモリーは未計測として `null` を記録します。

出力は `results.jsonl`・`summary.json`・`report.md`。`raw/` には合成値を含み得るためローカルに残し、
共有する場合は正規化結果と集計のみを使います。入力形式の多くはGitleaksルール由来なので、
この小規模corpusを検出器の総合ランキングと解釈しないでください。単独キーではペアcredentialの検出条件も再現しません。

GitHub hosted scannerは別コマンドです。自動アップロードは行いません。

```sh
python -m f4keenv github-benchmark OWNER/PRIVATE-REPO benchmark-local/evaluation-v1 --path-prefix corpus --output benchmark-local/github-results
```

privateリポジトリ・Secret Protectionの利用条件・secret scanning有効・validity checks無効を確認し、
Git treeのblobハッシュでローカルと同一のcorpusが配置されていることを検証してからalertを取得します。
API取得時点でsecret値を投影から除外し、レポートには含めません。スキャン完了未確認の段階では未検出をFNにしません。
hosted scanningの完了を確認した場合だけ `--scan-complete` を付けて採点します。
公開リポジトリは拒否します。利用可能なprivate実験先が未指定のため、GitHub hostedでの実測値はまだありません。

すべての値はローカルの乱数から生成します。実在キーの収集、認証情報の読み込み、
キー発行、サービスへの認証リクエストは行いません。値の接頭辞は形式に沿っていますが、
サービスで有効であることを意味しません。合成データであることはこの説明とマニフェストに記録します。

## 使い方

parts/UUID形式の旧生成器はPython 3.10以上で動きます。
拡張カタログのregex形式は `rstr==3.2.2` が必要です。通常はPython 3.11以上で `requirements-research.txt` を導入してください。

```sh
# 初回生成: 25形式それぞれ400件。既存出力には上書きしません。
python scripts/generate_dataset.py

# 別ディレクトリへ約1万件を生成（191形式 × 60件）
python scripts/generate_dataset.py --samples 60 --output benchmark-local/secrets-115-services

# 件数・形式・重複・SHA-256・パス・余分な.envを検証
python scripts/generate_dataset.py --check
python scripts/check_patterns.py
python -m unittest discover -s tests -v

# 既存121ファイルの再生成と検証
python scripts/generate_envs.py --force
python scripts/generate_envs.py --check
```

## 構成と根拠

- `catalog/services.json`: 形式、生成規則、出典、対応する検出ルール。
- `dataset/<format>/<sample>/.env`: 1ファイル1キー。
- `dataset/manifest.json`: 合成ラベル、ファイル一覧、ハッシュ。
- `research/pattern-results.json`: 公開ルールの正規表現との比較結果。

GitHub、Stripe、AWS、DigitalOcean、Shopify、Mailgun、npm、OpenAI、SendGrid、
Twilio、Slack、Discord、Datadog、Linear、Anthropic、Hypixel等の115サービスを対象とします。
同じサービスの異なるトークン種別は別の「形式」として数えます。
公開キーや識別子も含むため、全件が秘密鍵という分類ではありません。

Hypixel以外の190形式の根拠はGitleaksの公開検出定義です。参照コミットは
`5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c`。
[元定義](https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/config/gitleaks.toml)
は現行API仕様の保証ではなく、旧形式・ヒューリスティックを含みます。
正規表現の抜粋はGitleaks由来です。ライセンスは `research/GITLEAKS-LICENSE` を参照。

カタログの拡張を再実行するには `python scripts/expand_catalog.py` を使用します（Goが必要）。
上流の `RuleID` と定義ファイルを対応付け、JFrog/Artifactory等の宣言済みaliasを統合し、
一般形式や生成不能なルールは除外理由付きで `research/catalog-expansion.json` に記録します。
各追加形式を10 seed × 4文脈で生成し、Pythonでの形式検証に加えて元のGo/RE2 regexでも照合します。
上流ソース中のサンプルcredential値は取り込みません。
`catalog/services.json` を手動編集した場合は `collect --spec-limit 0` で出典台帳を同期してください。

`--samples` は**形式ごとの件数**です。191形式 × 60件で11,460件になります。
新しいdataset manifestは `service_count` と `format_count`、`samples_per_format` を別に持ち、
生成に使ったカタログを保存します。カタログ拡張後も旧10,000件のmanifestを検証できます。

拡張後の実行証跡は `research/service-expansion-verification.json`、191形式の照合結果は
`research/expanded-pattern-results.json` に保存しています。115サービス・1,528 fixtureに対する
3検出器の4,584判定は `benchmark/results/expanded-115/` を参照してください。
高忠実度の11,460件の値本体はローカルの `benchmark-local/secrets-115-services/` に保持し、
新しい値を公開GitHubへ自動追加する処理は含めません。

[Hypixel公式資料](https://api.hypixel.net/)は `API-Key` ヘッダーを確認できますが、
UUID形式の保証は確認できていません。HypixelのUUID v4サンプルは**近似形式**として
区別し、現行キー形式の確認済みデータや検出器の正例として扱いません。

## 評価上の限界

正規表現比較はPythonで実行します。Gitleaks本体のエントロピー判定、
除外設定、キーワード絞り込み、プロバイダーのチェックサム検証は再現しません。
オンラインでの有効性、Botの反応、GitHub検索・Trafficへの反映は未検証です。
GitHubのPush Protectionが合成キーを検知する場合があります。
保護設定を無効化する処理は含めません。
