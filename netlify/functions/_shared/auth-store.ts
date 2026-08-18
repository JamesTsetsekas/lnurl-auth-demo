import { getDeployStore, getStore } from "@netlify/blobs";
import type { Context } from "@netlify/functions";

export interface AuthStore {
  delete(key: string): Promise<void>;
  get<T>(key: string): Promise<T | null>;
  setJSON(key: string, value: unknown): Promise<void>;
}

function adaptStore(store: ReturnType<typeof getStore>): AuthStore {
  return {
    delete: (key) => store.delete(key),
    get: async <T>(key: string) =>
      (await store.get(key, { type: "json" })) as T | null,
    setJSON: async (key, value) => {
      await store.setJSON(key, value);
    },
  };
}

export function getAuthStore(context: Context): AuthStore {
  const options = {
    consistency: "strong" as const,
    name: "lightning-login-auth",
  };

  if (context.deploy.context === "production") {
    return adaptStore(getStore(options));
  }

  return adaptStore(getDeployStore(options));
}
