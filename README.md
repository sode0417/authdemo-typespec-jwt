# authdemo-typespec-jwt

契約駆動で学ぶ認証 API デモ（**TypeSpec → OpenAPI → ASP.NET Core 8**）

![CI](https://github.com/<your-account>/authdemo-typespec-jwt/actions/workflows/typespec.yml/badge.svg)

---

## 📖 概要

このリポジトリは、**TypeSpec** を単一のソースとして *OpenAPI 3.0 YAML* と *C# サーバースタブ* を自動生成し、JWT (Bearer) 認証付き API を実装する学習用プロジェクトです。契約ファーストで API を設計し、実装・テスト・ドキュメントをすべて契約に揃える **Contract‑Driven Development** を体験できます。

## 🗂 ディレクトリ構成

| パス                   | 説明                                            |
| -------------------- | --------------------------------------------- |
| `Spec/`              | TypeSpec 契約ファイル (`auth.tsp` など)               |
| `Generated/`         | 生成物 (OpenAPI YAML / C# スタブ) <br>※ **Git 管理外** |
| `.github/workflows/` | GitHub Actions 設定                             |

## 🚀 セットアップ (5 分で完了)

```bash
# 1. クローン
git clone https://github.com/<your-account>/authdemo-typespec-jwt.git
cd authdemo-typespec-jwt

# 2. 依存関係インストール
npm ci

# 3. TypeSpec をコンパイル
npm run tsp:compile  # => Generated/ に出力
```

> **必須ツール**
> ‑ Node.js 20+
> ‑ .NET SDK 8
> **推奨**: VS Code 拡張 *TypeSpec for VS Code*（構文ハイライトと補完が有効）

## 🛠 NPM スクリプト

| スクリプト                            | 説明                                                |
| -------------------------------- | ------------------------------------------------- |
| `npm run tsp:compile`            | TypeSpec をビルドし OpenAPI & C# スタブを `Generated/` に出力 |
| `npm run tsp:watch`<br>*(任意で追加)* | `Spec/` を監視し変更時に自動再コンパイル                          |

## 📏 開発ルール

1. **`Generated/` は手動編集・コミット禁止**
   必ず `.tsp` を修正して再コンパイルしてください。
2. すべての変更は **Pull Request** 経由で行い、CI が緑になることを確認します。
3. 契約変更に合わせてテスト・実装も更新し、親 Issue のチェックリストを反映します。

## 🤖 CI

GitHub Actions *TypeSpec Compile* ワークフローが **push / PR** 時に実行され、

* `npm ci → npm run tsp:compile` でビルド
* 生成物をアーティファクトとして保存

バッジが緑 = TypeSpec が正常にビルド出来ている証拠です。

## 🔗 参考リンク

* [TypeSpec 公式ドキュメント](https://aka.ms/typespec)
* [.NET 8 SDK ダウンロード](https://dotnet.microsoft.com/download/dotnet/8.0)

---

📄 **ライセンス**: MIT
