# F4KEENV

多数のAPIサービスの認証情報を模した合成シークレット・データセット。
新しいデータセットは **16サービス・25形式 × 400件 = 10,000件**。
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
旧カタログ25形式も台帳に取り込みますが、識別の根拠が異なるため `catalog:` 名前空間の未検証候補とします。
ドメインの所有関係、買収、製品間の統合を推測して自動マージする処理は含めません。

OpenAPI解析はSwagger 2.0 / OpenAPI 3.xのJSONに対応します。ルートと操作ごとのsecurity、
OR/ANDの要件、匿名アクセス、ローカルJSON Pointer参照、OAuth flow、OIDC、mTLS、apiKeyの配置を保持します。
外部参照・循環参照・未定義schemeは問題として残します。YAMLや複数ファイル仕様の自動解決には未対応です。
`bearerFormat` はヒントとして保持し、キーの文字列表現や内部発行アルゴリズムへ変換しません。

**候補サービス数・認証方式を観測したサービス数・公式確認済みサービス数を別に集計します。**
集約ディレクトリと検出器からの情報は公式確認に昇格させません。不明な形式・発行方式は `unknown` のままです。
10,000件の合成キーを10,000サービスの調査完了とは数えません。

現在の範囲はP0の収集・出典・解析・検証基盤です。公式docsの再帰検索、
人手監査、4検出器の実行比較、public-safe corpusへの移行は未実装です。
この収集コマンドは既存の公開合成データを変更・再生成・再公開しません。

すべての値はローカルの乱数から生成します。実在キーの収集、認証情報の読み込み、
キー発行、サービスへの認証リクエストは行いません。値の接頭辞は形式に沿っていますが、
サービスで有効であることを意味しません。合成データであることはこの説明とマニフェストに記録します。

## 使い方

キー生成器はPython 3.10以上。生成器自体に外部パッケージは不要です。

```sh
# 初回生成: 25形式それぞれ400件。既存出力には上書きしません。
python scripts/generate_dataset.py

# 別ディレクトリへ新しい1万件を生成
python scripts/generate_dataset.py --samples 400 --output another-dataset

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
Twilio、Slack、Discord、Datadog、Linear、Anthropic、Hypixelを対象とします。
同じサービスの異なるトークン種別は別の「形式」として数えます。
公開キーや識別子も含むため、全件が秘密鍵という分類ではありません。

24形式の根拠はGitleaksの公開検出定義です。参照コミットは
`5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c`。
[元定義](https://github.com/gitleaks/gitleaks/blob/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c/config/gitleaks.toml)
は現行API仕様の保証ではなく、旧形式・ヒューリスティックを含みます。
正規表現の抜粋はGitleaks由来です。ライセンスは `research/GITLEAKS-LICENSE` を参照。

[Hypixel公式資料](https://api.hypixel.net/)は `API-Key` ヘッダーを確認できますが、
UUID形式の保証は確認できていません。HypixelのUUID v4サンプルは**近似形式**として
区別し、現行キー形式の確認済みデータや検出器の正例として扱いません。

## 評価上の限界

正規表現比較はPythonで実行します。Gitleaks本体のエントロピー判定、
除外設定、キーワード絞り込み、プロバイダーのチェックサム検証は再現しません。
オンラインでの有効性、Botの反応、GitHub検索・Trafficへの反映は未検証です。
GitHubのPush Protectionが合成キーを検知する場合があります。
保護設定を無効化する処理は含めません。
