import "@typespec/http";
import "@typespec/rest";
import "@typespec/openapi";
import "./auth.tsp";

using TypeSpec.Http;
using TypeSpec.Rest;

@doc("AuthDemo API")
@server("https://localhost:5173", "Local development server")
namespace AuthDemo;

model BearerAuth extends TypeSpec.Http.BearerAuth {
  bearerFormat: "JWT";
}

@useAuth(BearerAuth)
interface Operations extends AuthOperations {}
