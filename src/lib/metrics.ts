type CounterKey =
  | "jobsCreated"
  | "jobsExpired"
  | "artifactsDownloaded"
  | "recipesRun"
  | "clientErrors"
  | "serverErrors";

const counters: Record<CounterKey, number> = {
  jobsCreated: 0,
  jobsExpired: 0,
  artifactsDownloaded: 0,
  recipesRun: 0,
  clientErrors: 0,
  serverErrors: 0
};

export function incrementMetric(key: CounterKey, amount = 1) {
  counters[key] += amount;
}

export function getMetricsSnapshot() {
  return { ...counters };
}
