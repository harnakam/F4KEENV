# F4KEENV

多数のAPIサービスの認証情報を模した合成シークレット・データセット。
新しいデータセットは **16サービス・25形式 × 400件 = 10,000件**。
既存の121個の環境設定ファイルも保持しています。

すべての値はローカルの乱数から生成します。実在キーの収集、認証情報の読み込み、
キー発行、サービスへの認証リクエストは行いません。値の接頭辞は形式に沿っていますが、
サービスで有効であることを意味しません。合成データであることはこの説明とマニフェストに記録します。

## 使い方

Python 3.10以上。外部パッケージ不要。

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
