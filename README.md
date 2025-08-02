# AuthDemo API

JWT認証を使用したデモAPI

## 開発環境のセットアップ

### 必要条件

- .NET 8.0
- PostgreSQL
- Node.js (TypeSpecコンパイル用)

### データベースの準備

1. PostgreSQLをインストール
2. データベースを作成:
```sql
CREATE DATABASE authdemo;
```

### アプリケーションの設定

1. リポジトリをクローン
```bash
git clone https://github.com/yourusername/authdemo-typespec-jwt.git
```

2. 依存関係をインストール
```bash
cd authdemo-typespec-jwt
dotnet restore
```

3. マイグレーションを実行
```bash
dotnet ef database update --project src/AuthDemo.Infrastructure --startup-project src/AuthDemo.Api
```

4. appsettings.Development.jsonの設定
```json
{
  "ConnectionStrings": {
    "Default": "Host=localhost;Database=authdemo;Username=postgres;Password=postgres"
  },
  "Jwt": {
    "Issuer": "AuthDemo",
    "Audience": "AuthDemo"
  }
}
```

環境変数 `JWT_KEY` に秘密鍵を設定します。
```bash
export JWT_KEY=your-development-jwt-key
```

## APIの実行

```bash
dotnet run --project src/AuthDemo.Api
```

## 認証機能の使用方法

APIは以下の認証関連エンドポイントを提供:

### 1. サインアップ (POST /auth/signup)
```json
{
  "username": "user@example.com",
  "password": "password123"
}
```

### 2. サインイン (POST /auth/signin)
```json
{
  "username": "user@example.com",
  "password": "password123"
}
```
レスポンスとしてJWTトークンが返却されます。

### 3. 保護されたエンドポイント

認証が必要なエンドポイントにアクセスする際は、HTTPヘッダーにトークンを設定:
```
Authorization: Bearer {token}
```

## Swagger UI

開発環境では、以下のURLでSwagger UIにアクセスできます：
http://localhost:5173/swagger

## CI/CD

GitHub Actionsを使用して以下を自動化:
- TypeSpecのコンパイル
- .NETのビルドとテスト
- DBマイグレーション

# GitHub Actionsテスト
- 以下はワークフロー起動のためのテストです。その4