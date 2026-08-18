import type { Config, Context } from "@netlify/functions";

import { handleAuthRequest } from "./_shared/auth-app.js";
import { getAuthStore } from "./_shared/auth-store.js";

export default async (request: Request, context: Context): Promise<Response> => {
  const callbackOrigin =
    context.deploy.context === "production"
      ? context.site.url
      : new URL(request.url).origin;
  return handleAuthRequest(request, getAuthStore(context), { callbackOrigin });
};

export const config: Config = {
  path: ["/login", "/auth/callback", "/auth/status", "/success", "/logout"],
};
