import "@typespec/http";
import "@typespec/rest";

using TypeSpec.Http;
using TypeSpec.Rest;

namespace AuthDemo;

@route("/auth")
interface AuthOperations {
  @route("signup")
  @post
  signUp(@body signUpRequest: SignUpRequest): SignUpResponse | ErrorResponse;

  @route("signin")
  @post
  signIn(@body signInRequest: SignInRequest): SignInResponse | ErrorResponse;
}

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

model ErrorResponse {
  error: string;
}
