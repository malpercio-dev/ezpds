// Railway infrastructure as code for the `ezpds` project: every service, volume, and
// bucket in both environments. Railway does NOT read this file at deploy time — it is
// desired state that `railway config plan` diffs against an environment and
// `railway config apply` writes into it. Deploys themselves still come from Railway's
// GitHub integration (staging watches `main`, production watches `production`).
//
// Operating procedure, and what is deliberately different between the two environments:
// docs/deploy.md → "Railway configuration (infrastructure as code)".
import { bucket, defineRailway, github, group, image, postgres, project, service, volume } from "railway/iac";

const REPO = "malpercio-dev/ezpds";
const GIB = 1_000_000_000;

export default defineRailway((ctx) => {
  const prod = ctx.isEnvironment("production");
  const branch = prod ? "production" : "main";

  // `checkSuites: true` is the dashboard's "Wait for CI": Railway holds a deploy until the
  // commit's GitHub checks are green.
  const waitForCi = github(REPO, { branch, checkSuites: true });

  // Every service built from this repo restarts on failure, at most three times.
  const restart = { restartPolicyType: "ON_FAILURE", restartPolicyMaxRetries: 3 } as const;
  const dockerfile = (dockerfilePath: string, watchPatterns?: string[]) => ({
    buildEnvironment: "V3" as const,
    builder: "DOCKERFILE" as const,
    dockerfilePath,
    ...(watchPatterns ? { watchPatterns } : {}),
  });
  const limits = (cpu: number) => ({ limitOverride: { containers: { cpu, memoryBytes: GIB } } });

  const alerts = { usage: { "100": {}, "80": {}, "95": {} } };
  const disk = (name: string, region: string, sizeMB: number) =>
    volume(name, { alerts, allowOnlineResize: true, region, sizeMB });

  // --- Volumes. Names differ per environment (Railway suffixes forked volumes). -----------
  const pdsData = disk(prod ? "ezpds-volume" : "ezpds-volume-XbRF", "sfo", 500);
  const relayData = disk(prod ? "ezpds-volume-Tw4e" : "custos-notify-relay-volume", "us-west2", 5000);
  const litestreamBackup = bucket("ezpds-litestream-backup", { region: "sjc" });

  // --- PDS (repo-root build context, root Dockerfile) ------------------------------------
  const custosObsign = service("custos-obsign", {
    source: waitForCi,
    build: dockerfile("Dockerfile"),
    // The PDS returns 200 here when the DB is up.
    healthcheck: "/xrpc/_health",
    healthcheckTimeout: 30,
    replicas: { sfo: 1 },
    deploy: {
      ...restart,
      ipv6EgressEnabled: true,
      ...(prod ? {} : { ...limits(1), sleepApplication: true }),
    },
    ...(prod ? { domains: ["*.obsign.org", "pds.obsign.org"] } : {}),
    networking: { privateNetworkEndpoint: "ezpds" },
    volumeMounts: { "/data": pdsData },
  });

  // --- Notification relay (repo-root build context: cargo resolves the whole workspace) ---
  // No healthcheck: the relay serves no HTTP port (it is dialed over QUIC by iroh node id),
  // so process liveness plus the restart policy is the whole health story.
  const custosNotifyRelay = service("custos-notify-relay", {
    // Staging does not wait for CI on this service; kept as found.
    source: prod ? waitForCi : github(REPO, { branch }),
    build: dockerfile("crates/notify-relay/Dockerfile", [
      "crates/notify-relay/**",
      "crates/common/**",
      "Cargo.toml",
      "Cargo.lock",
    ]),
    replicas: { "us-west2": 1 },
    deploy: { ...restart, ipv6EgressEnabled: true, ...limits(0.5) },
    networking: { privateNetworkEndpoint: "ezpds-4f2a" },
    volumeMounts: { "/data": relayData },
  });

  // --- MCP sidecar (repo-root build context: it single-sources tools/mcp) -----------------
  const obsignMcpVolume = disk("obsign-mcp-volume", "us-west2", 5000); // production only
  const obsignMcp = service("obsign-mcp", {
    source: waitForCi,
    build: dockerfile("tools/mcp-sidecar/Dockerfile", ["/tools/mcp-sidecar/**"]),
    // The sidecar answers 200 at "/" (a liveness probe that touches no credential).
    healthcheck: "/",
    healthcheckTimeout: 30,
    replicas: { "us-west2": 1 },
    deploy: { ...restart, ...limits(1), sleepApplication: true },
    ...(prod ? { domains: ["mcp.obsign.org"], volumeMounts: { "/uploaded-blobs": obsignMcpVolume } } : {}),
  });

  // --- Static sites (Root Directory = the site's subtree; Dockerfile path is relative to it)
  const site = (name: string, rootDirectory: string, endpoint: string, domains: string[], checkSuites = true) =>
    service(name, {
      source: github(REPO, { branch, rootDirectory, ...(checkSuites ? { checkSuites } : {}) }),
      build: dockerfile("Dockerfile", [`${rootDirectory}/**`]),
      // Caddy serves the site root; a 200 there means the service is up.
      healthcheck: "/",
      healthcheckTimeout: 30,
      replicas: { "us-west2": 1 },
      deploy: { ...restart, ...limits(0.5), sleepApplication: true },
      ...(prod ? { domains } : {}),
      networking: { privateNetworkEndpoint: endpoint },
    });

  // Staging does not wait for CI on the docs site (and pins no branch, which Railway reads
  // as the default branch, `main`); kept as found.
  const obsignDocs = site("obsign-docs", "/sites/docs", "ezpds-1b0e", ["docs.obsign.org"], prod);
  const obsignMarketing = site("obsign-marketing", "/sites/marketing", "practical-strength", ["about.obsign.org", "obsign.org"]);
  if (prod) {
    obsignDocs.cdn = { enabled: true, purgeOnDeploy: "all" };
    obsignMarketing.cdn = { enabled: true, purgeOnDeploy: "all" };
  } else {
    obsignMarketing.cdn = { enabled: true };
  }

  const shared = [custosObsign, custosNotifyRelay, obsignMcp, obsignDocs, obsignMarketing, pdsData, relayData, litestreamBackup];

  if (!prod) {
    // An unattached leftover in staging; declared so that an apply does not delete it.
    const orphan = disk("ezpds-volume", "sfo", 500);
    return project("ezpds", { variables: { managed: false }, resources: [...shared, orphan] });
  }

  // --- Production only: blob backup bucket and the Umami analytics stack ------------------
  const obsignBlobstoreBackup = bucket("obsign-blobstore-backup", { region: "sjc" });
  const Postgres = postgres("Postgres", { region: "us-west2" });
  Postgres.networking = { privateNetworkEndpoint: "postgres" };
  const postgresVolume = disk("postgres-volume", "us-west2", 5000);
  const valkeyVolume = disk("valkey-volume", "us-west2", 5000);
  const Valkey = service("Valkey", {
    source: image("valkey/valkey:latest"),
    build: { buildEnvironment: "V3", builder: "RAILPACK" },
    start: '/bin/sh -c "exec docker-entrypoint.sh valkey-server --port ${VALKEY_PORT} --requirepass ${VALKEY_PASSWORD}"',
    replicas: { "us-west2": 1 },
    networking: { privateNetworkEndpoint: "valkey" },
    volumeMounts: { "/data": valkeyVolume },
  });
  const umami = service("umami", {
    source: image("umamisoftware/umami:postgresql-latest"),
    build: { buildEnvironment: "V3", builder: "RAILPACK" },
    healthcheck: "/api/heartbeat",
    replicas: { "us-west2": 1 },
    deploy: { sleepApplication: true },
    domains: ["analytics.obsign.org"],
  });
  const Umami = group("Umami", [Valkey, umami, Postgres]);

  return project("ezpds", {
    // Variables and secrets stay in Railway; an apply never reads or writes them.
    variables: { managed: false },
    resources: [...shared, obsignMcpVolume, postgresVolume, valkeyVolume, obsignBlobstoreBackup, Umami],
  });
});
