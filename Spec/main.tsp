import "@typespec/http";
import "@typespec/rest";
import "./auth.tsp";

using TypeSpec.Http;
using TypeSpec.Rest;

@doc("AuthDemo API")
@server("https://localhost:5173", "Local development server")
namespace AuthDemo;

interface Operations extends AuthOperations {}
