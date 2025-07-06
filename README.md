# authdemo-typespec-jwt

契約駆動で学ぶ認証 API デモ  
**TypeSpec → OpenAPI → ASP.NET Core 8 + EF Core 8 + PostgreSQL + JWT**

[![CI](https://github.com/sode0417/authdemo-typespec-jwt/actions/workflows/ci.yml/badge.svg)](https://github.com/sode0417/authdemo-typespec-jwt/actions/workflows/ci.yml)

---

## 📖 概要

* **TypeSpec** で API 契約 (`.tsp`) を書く  
* ~~OpenAPI だけ~~ → *OpenAPI 3.0 YAML* と *C# Minimal-API スタブ* を **自動生成**  
* **EF Core 8** & **PostgreSQL 16** で永続化  
* **JWT (Bearer)** 認証を実装予定

“契約ファースト” で **実装・テスト・ドキュメント** を 1 枚の契約に揃える  
**Contract-Driven Development** をハンズオンで体験できます。

---

## 🗂️ プロジェクト構成

| パス | 役割 |
|------|------|
| `Spec/` | TypeSpec 契約 (`auth.tsp` など) |
| `Generated/` | OpenAPI YAML / C# スタブ **※Git 管理しない** |
| `src/AuthDemo.Api/` | ASP.NET Core 8 ― Web API (Minimal) |
| `src/AuthDemo.Infrastructure/` | `ApplicationDbContext`, エンティティ, マイグレーション |
| `.github/workflows/` | CI (TypeSpec + .NET + Postgres) |

---

## 🚀 クイックスタート

```bash
# 1. Clone
git clone https://github.com/sode0417/authdemo-typespec-jwt.git
cd authdemo-typespec-jwt

# 2. Install deps
npm ci            # TypeSpec
dotnet restore    # .NET projects

# 3. Compile TypeSpec → OpenAPI & C#
npm run tsp:compile           # => Generated/

# 4. Start PostgreSQL
docker compose up -d db       # service name = "db"

# 5. (first time only) apply migrations
dotnet ef database update \
  -p src/AuthDemo.Infrastructure \
  -s src/AuthDemo.Api

# 6. Run API
dotnet run --project src/AuthDemo.Api
# → http://localhost:5173  (Swagger = /swagger)
````

> **必要ツール**
>
> * **Node.js 20+**
> * **.NET SDK 8.x**
> * **Docker Desktop + WSL2** (Windows) ／ **Docker Engine** (macOS/Linux)
>   *（任意）VS Code 拡張 *TypeSpec for VS Code* – 構文ハイライト & 補完*

---

## 🐘 PostgreSQL 接続文字列

| 用途                      | 例                                                                                           | 補足                                                                                  |
| ----------------------- | ------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| **ローカル開発**              | `Host=host.docker.internal;Port=5432;Database=authdemo;Username=postgres;Password=postgres` | Docker Desktop から Windows ホストへ                                                      |
| **CI / GitHub Actions** | `Pg__ConnectionString` 環境変数                                                                 | 例: `Host=localhost;Port=5432;Database=authdemo;Username=postgres;Password=postgres` |

* `appsettings.Development.json` の DSN → ローカル用
* **本番 / CI** は環境変数で上書き

---

## 💡 NPM スクリプト

| スクリプト         | 説明                              |
| ------------- | ------------------------------- |
| `tsp:compile` | TypeSpec をビルドし `Generated/` へ出力 |
| `tsp:watch`   | `Spec/` を監視して自動再ビルド             |

---

## 🤖 CI（GitHub Actions）

```yaml
# .github/workflows/ci.yml
services:
  postgres:
    image: postgres:16-alpine
    env:
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: authdemo
    ports: ['5432:5432']

steps:
  - uses: actions/checkout@v4

  - name: Setup .NET 8
    uses: actions/setup-dotnet@v3
    with: { dotnet-version: '8.0.x' }

  - name: Restore & Build
    run: dotnet build --configuration Release --no-restore

  - name: Apply EF Core migrations
    env:
      Pg__ConnectionString: Host=localhost;Port=5432;Database=authdemo;Username=postgres;Password=postgres
    run: dotnet ef database update --no-build \
          -p src/AuthDemo.Infrastructure -s src/AuthDemo.Api
```

バッジが **緑** = TypeSpec ビルド & マイグレーションが成功。

---

## 📏 開発ルール

1. **`Generated/` はコミットしない**
   契約を変えたら `npm run tsp:compile` を忘れずに。
2. 変更は **Pull Request** 経由。CI を緑にしてマージ。
3. 親 Issue に紐づくチェックリストを更新して **CDD** を徹底。

---

## 📝 よくあるハマりポイント

| 症状                                                        | 原因 & 解決                                                                                                     |
| --------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `…doesn't reference Microsoft.EntityFrameworkCore.Design` | *Design* パッケージは **どこか 1 プロジェクト**にあれば OK。<br>`src/AuthDemo.Infrastructure` だけに入れて `PrivateAssets="all"` にする。 |
| `Connection refused (127.0.0.1:5432)`                     | Docker 版 Postgres へ接続するときは **`host.docker.internal`** を使う（Windows/mac）。                                     |
| マイグレーション No actions                                       | 既に DB が最新。`dotnet ef migrations add <name>` で追加 → `database update`                                         |

---

## 🔗 参考リンク

* **TypeSpec** – [https://aka.ms/typespec](https://aka.ms/typespec)
* **.NET 8 SDK** – [https://dotnet.microsoft.com/download/dotnet/8.0](https://dotnet.microsoft.com/download/dotnet/8.0)
* **EF Core + PostgreSQL (Npgsql)** – [https://learn.microsoft.com/ef/core/providers/npgsql/](https://learn.microsoft.com/ef/core/providers/npgsql/)

---

📄 **License**: MIT