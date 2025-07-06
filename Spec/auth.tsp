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

// Auth models
model SignUpRequest {
  username: string;
  password: string;
}

model SignUpResponse {
  id: string;
  username: string;
}

model SignInRequest {
  username: string;
  password: string;
}

model SignInResponse {
  token: string;
  username: string;
}

@route("/auth")
namespace Auth {
  @route("/signup")
  @post
  op signUp(@body body: SignUpRequest): SignUpResponse;

  @route("/signin")
  @post
  op signIn(@body body: SignInRequest): SignInResponse;
}
