// Spec/auth.tsp
import "@typespec/http";
using Http;

@service
namespace AuthService;

model VersionResponse {
  version: string;
}

@route("/version")
op getVersion(): VersionResponse;
