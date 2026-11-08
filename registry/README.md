# Research snapshot

公開ソースの抽出メタデータです。raw OpenAPI本文や高忠実度benchmarkのcredential値は含めません。
`manifest.json` はJSONLファイルの行数・SHA-256と、候補数・認証観測数・公式確認済み数を別々に記録します。

`ingestion-report.json` は全2,529候補への仕様取得の実行記録です。
2,527件を解析し、Microsoft Graphの2仕様は32MiBの応答上限超過として記録しています。
これは10,000サービスを公式確認済みという結果ではありません。

`audit-sample.jsonl` は未実施の人手監査キューです。`review_status:pending` を監査済みと解釈しないでください。
`tasks.jsonl` の検索語も未実行であり、検索済みの根拠としては扱いません。

スナップショット再生成例:

```sh
python -m f4keenv collect --spec-limit 10000 --workers 4
python -m f4keenv schedule --limit 100 --output work/research-next.jsonl
python -m f4keenv audit-sample --output work/audit-sample.jsonl
python -m f4keenv export --output registry-new
```

取得上限などで一部仕様が失敗するとcollectは終了コード1を返しますが、成功した仕様と失敗理由を保存します。
