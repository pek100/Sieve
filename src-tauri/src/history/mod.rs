//! Persisted activity history (plan row 77): per-app, per-minute counts of
//! active connections, rolled up to hours and days, in one SQLite file under
//! the app's data dir (`history.sqlite3`). Nothing outside that dir is written.
//!
//! Roll-up happens on write: every sample is added to its minute, hour and
//! day bucket in one transaction, and each grain is pruned past its retention
//! (`Grain::keep_ms`). So every grain is complete for as long as it is kept,
//! and a reader never has to stitch grains together.
//!
//! Absent is not zero: `samples` says how many samples a bucket holds. A
//! bucket with samples and no row for an app means that app had 0 active
//! flows; a bucket with no samples means Sieve was not sampling.

use rusqlite::{Connection, OptionalExtension, params};

use crate::protocol::{
    AppBucket, Grain, History, HistoryQuery, HistoryRecord, PROTOCOL_VERSION, SampleBucket,
};

/// Schema version stored in `PRAGMA user_version`.
pub const HISTORY_SCHEMA: i64 = 1;

#[derive(Debug, thiserror::Error)]
pub enum HistoryError {
    #[error("history database: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("history database has schema {found}, newer than this Sieve ({HISTORY_SCHEMA}); update Sieve")]
    NewerSchema { found: i64 },
    #[error("history step {step} ms is not a whole number of {grain:?} buckets")]
    BadStep { grain: Grain, step: u64 },
    #[error("history time {0} is out of range")]
    Time(u64),
    #[error("history could not be opened: {0}")]
    Open(String),
}

/// Schema steps: STEPS[n] upgrades a schema-n database to n + 1.
const STEPS: [&str; 1] = [
    // 0 -> 1: samples per bucket, flows per app per bucket. Grain is the
    // index into protocol::GRAIN_NAMES (0 minute, 1 hour, 2 day).
    "CREATE TABLE samples (
        grain INTEGER NOT NULL,
        t     INTEGER NOT NULL,
        n     INTEGER NOT NULL,
        PRIMARY KEY (grain, t)
    ) WITHOUT ROWID;
    CREATE TABLE app_flows (
        grain INTEGER NOT NULL,
        t     INTEGER NOT NULL,
        app   TEXT    NOT NULL,
        name  TEXT    NOT NULL,
        flows INTEGER NOT NULL,
        PRIMARY KEY (grain, t, app)
    ) WITHOUT ROWID;",
];

fn sql_time(t: u64) -> Result<i64, HistoryError> {
    i64::try_from(t).map_err(|_| HistoryError::Time(t))
}

fn grain_code(g: Grain) -> i64 {
    // index() is 0..=2, always fits.
    g.index() as i64
}

/// Start of the bucket of `grain` that holds `t`.
pub fn bucket_start(t: u64, grain: Grain) -> u64 {
    t - t % grain.ms()
}

pub struct HistoryStore {
    conn: Connection,
    /// Minute of the last prune; pruning runs at most once per minute.
    pruned_minute: Option<u64>,
}

impl HistoryStore {
    pub fn open(path: &std::path::Path) -> Result<Self, HistoryError> {
        Self::with(Connection::open(path)?)
    }

    pub fn open_in_memory() -> Result<Self, HistoryError> {
        Self::with(Connection::open_in_memory()?)
    }

    fn with(mut conn: Connection) -> Result<Self, HistoryError> {
        migrate(&mut conn)?;
        Ok(Self { conn, pruned_minute: None })
    }

    pub fn schema(&self) -> Result<i64, HistoryError> {
        Ok(self.conn.query_row("PRAGMA user_version", [], |r| r.get(0))?)
    }

    /// Fold one sample into every grain, then prune what is past retention.
    pub fn record(&mut self, rec: &HistoryRecord) -> Result<(), HistoryError> {
        let tx = self.conn.transaction()?;
        {
            let mut add_sample = tx.prepare_cached(
                "INSERT INTO samples (grain, t, n) VALUES (?1, ?2, 1)
                 ON CONFLICT (grain, t) DO UPDATE SET n = n + 1",
            )?;
            let mut add_flows = tx.prepare_cached(
                "INSERT INTO app_flows (grain, t, app, name, flows) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (grain, t, app) DO UPDATE SET flows = flows + excluded.flows, name = excluded.name",
            )?;
            for grain in Grain::ALL {
                let t = sql_time(bucket_start(rec.t, grain))?;
                add_sample.execute(params![grain_code(grain), t])?;
                for a in rec.apps.iter().filter(|a| a.flows > 0) {
                    add_flows.execute(params![grain_code(grain), t, a.app, a.name, sql_time(a.flows)?])?;
                }
            }
        }
        tx.commit()?;
        let minute = bucket_start(rec.t, Grain::Minute);
        if self.pruned_minute != Some(minute) {
            self.prune(rec.t)?;
            self.pruned_minute = Some(minute);
        }
        Ok(())
    }

    /// Drop every bucket older than its grain's retention, measured back from `now`.
    pub fn prune(&mut self, now: u64) -> Result<(), HistoryError> {
        let tx = self.conn.transaction()?;
        for grain in Grain::ALL {
            let before = sql_time(now.saturating_sub(grain.keep_ms()))?;
            tx.execute("DELETE FROM samples WHERE grain = ?1 AND t < ?2", params![grain_code(grain), before])?;
            tx.execute("DELETE FROM app_flows WHERE grain = ?1 AND t < ?2", params![grain_code(grain), before])?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Buckets of one grain in [from, to), summed into `step`-wide buckets.
    pub fn read(&self, q: &HistoryQuery) -> Result<History, HistoryError> {
        let gms = q.grain.ms();
        if q.step == 0 || !q.step.is_multiple_of(gms) {
            return Err(HistoryError::BadStep { grain: q.grain, step: q.step });
        }
        let (g, from, to, step) = (grain_code(q.grain), sql_time(q.from)?, sql_time(q.to)?, sql_time(q.step)?);

        let mut st = self.conn.prepare_cached(
            "SELECT (t / ?4) * ?4 AS b, SUM(n) FROM samples
             WHERE grain = ?1 AND t >= ?2 AND t < ?3 GROUP BY b ORDER BY b",
        )?;
        let samples = st
            .query_map(params![g, from, to, step], |r| {
                Ok(SampleBucket { t: r.get::<_, i64>(0)?.max(0) as u64, n: r.get::<_, i64>(1)?.max(0) as u64 })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let mut st = self.conn.prepare_cached(
            "SELECT (t / ?4) * ?4 AS b, app, MAX(name), SUM(flows) FROM app_flows
             WHERE grain = ?1 AND t >= ?2 AND t < ?3 GROUP BY b, app ORDER BY b, app",
        )?;
        let apps = st
            .query_map(params![g, from, to, step], |r| {
                Ok(AppBucket {
                    t: r.get::<_, i64>(0)?.max(0) as u64,
                    app: r.get(1)?,
                    name: r.get(2)?,
                    flows: r.get::<_, i64>(3)?.max(0) as u64,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(History { v: PROTOCOL_VERSION, grain: q.grain, step: q.step, samples, apps })
    }
}

/// Bring the database to HISTORY_SCHEMA. A newer database is refused, never rewritten.
fn migrate(conn: &mut Connection) -> Result<(), HistoryError> {
    let found: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if found > HISTORY_SCHEMA {
        return Err(HistoryError::NewerSchema { found });
    }
    let tx = conn.transaction()?;
    for (n, step) in STEPS.iter().enumerate().skip(usize::try_from(found).unwrap_or(0)) {
        tx.execute_batch(step)?;
        tx.pragma_update(None, "user_version", n as i64 + 1)?;
    }
    tx.commit()?;
    // Busy file on a slow disk: wait a little instead of failing a sample.
    conn.busy_timeout(std::time::Duration::from_millis(500))?;
    let _: Option<String> = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0)).optional()?;
    Ok(())
}

/// The store as Tauri managed state. Opening can fail (disk, permissions,
/// newer schema); the error is kept and every history command reports it.
pub struct HistoryState(pub std::sync::Mutex<Result<HistoryStore, String>>);

impl HistoryState {
    pub fn open_at(dir: &std::path::Path) -> Self {
        let opened = std::fs::create_dir_all(dir)
            .map_err(|e| HistoryError::Open(e.to_string()))
            .and_then(|_| HistoryStore::open(&dir.join("history.sqlite3")))
            .map_err(|e| e.to_string());
        Self(std::sync::Mutex::new(opened))
    }

    pub fn with<T>(&self, f: impl FnOnce(&mut HistoryStore) -> Result<T, HistoryError>) -> Result<T, String> {
        let mut guard = self.0.lock().map_err(|_| "history lock poisoned".to_string())?;
        match guard.as_mut() {
            Ok(store) => f(store).map_err(|e| e.to_string()),
            Err(e) => Err(e.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::AppCount;

    const MIN: u64 = 60_000;
    const HOUR: u64 = 3_600_000;
    const DAY: u64 = 86_400_000;
    /// 2026-10-17T00:00:00Z, a day boundary.
    const T0: u64 = 1_792_195_200_000;

    fn rec(t: u64, apps: &[(&str, u64)]) -> HistoryRecord {
        HistoryRecord {
            t,
            apps: apps.iter().map(|(a, f)| AppCount { app: (*a).into(), name: a.to_uppercase(), flows: *f }).collect(),
        }
    }

    fn q(from: u64, to: u64, grain: Grain, step: u64) -> HistoryQuery {
        HistoryQuery { from, to, grain, step }
    }

    #[test]
    fn a_new_database_migrates_to_schema_1_and_reopens_without_change() {
        let dir = std::env::temp_dir().join(format!("sieve-history-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("h.sqlite3");
        {
            let mut s = HistoryStore::open(&path).expect("opens");
            assert_eq!(s.schema().expect("schema"), HISTORY_SCHEMA);
            s.record(&rec(T0, &[("chrome", 3)])).expect("records");
        }
        let s = HistoryStore::open(&path).expect("reopens");
        assert_eq!(s.schema().expect("schema"), 1);
        let h = s.read(&q(T0, T0 + MIN, Grain::Minute, MIN)).expect("reads");
        assert_eq!(h.apps.len(), 1, "data survives a reopen");
        drop(s);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_newer_schema_is_refused_not_rewritten() {
        let conn = Connection::open_in_memory().expect("mem");
        conn.pragma_update(None, "user_version", 7).expect("set");
        match HistoryStore::with(conn) {
            Err(HistoryError::NewerSchema { found: 7 }) => {}
            Err(e) => panic!("wrong error {e}"),
            Ok(_) => panic!("a newer schema must be refused"),
        }
    }

    #[test]
    fn one_sample_lands_in_its_minute_hour_and_day() {
        let mut s = HistoryStore::open_in_memory().expect("mem");
        let t = T0 + 5 * HOUR + 17 * MIN + 12_345;
        s.record(&rec(t, &[("chrome", 4), ("idle", 0)])).expect("records");
        for g in Grain::ALL {
            let h = s.read(&q(T0, T0 + DAY, g, g.ms())).expect("reads");
            assert_eq!(h.samples, vec![SampleBucket { t: bucket_start(t, g), n: 1 }], "{g:?}");
            // An app with 0 flows writes no row: absent in a sampled bucket reads as 0.
            assert_eq!(h.apps.len(), 1, "{g:?}");
            assert_eq!(h.apps[0].flows, 4);
            assert_eq!(h.apps[0].name, "CHROME");
        }
    }

    #[test]
    fn hour_and_day_are_the_sum_of_their_minutes() {
        let mut s = HistoryStore::open_in_memory().expect("mem");
        // 3 hours at one sample per 20 s, chrome's count varying with time.
        let mut t = T0;
        while t < T0 + 3 * HOUR {
            let n = (t / 20_000) % 7;
            s.record(&rec(t, &[("chrome", n), ("slack", 1)])).expect("records");
            t += 20_000;
        }
        let minutes = s.read(&q(T0, T0 + DAY, Grain::Minute, HOUR)).expect("minutes by hour");
        let hours = s.read(&q(T0, T0 + DAY, Grain::Hour, HOUR)).expect("hours");
        assert_eq!(minutes.samples, hours.samples);
        assert_eq!(minutes.apps, hours.apps);
        assert_eq!(hours.samples.len(), 3);
        assert!(hours.samples.iter().all(|b| b.n == 180));

        let hours_by_day = s.read(&q(T0, T0 + DAY, Grain::Hour, DAY)).expect("hours by day");
        let days = s.read(&q(T0, T0 + DAY, Grain::Day, DAY)).expect("days");
        assert_eq!(hours_by_day.apps, days.apps);
        assert_eq!(days.samples, vec![SampleBucket { t: T0, n: 540 }]);
    }

    #[test]
    fn step_must_be_a_whole_number_of_grain_buckets() {
        let s = HistoryStore::open_in_memory().expect("mem");
        assert!(matches!(s.read(&q(0, 1, Grain::Hour, 90 * MIN)), Err(HistoryError::BadStep { .. })));
        assert!(matches!(s.read(&q(0, 1, Grain::Minute, 0)), Err(HistoryError::BadStep { .. })));
        assert!(s.read(&q(0, 1, Grain::Hour, 2 * HOUR)).is_ok());
    }

    #[test]
    fn range_is_from_inclusive_to_exclusive() {
        let mut s = HistoryStore::open_in_memory().expect("mem");
        s.record(&rec(T0, &[("a", 1)])).expect("rec");
        s.record(&rec(T0 + MIN, &[("a", 1)])).expect("rec");
        let h = s.read(&q(T0, T0 + MIN, Grain::Minute, MIN)).expect("reads");
        assert_eq!(h.samples.len(), 1);
        assert_eq!(h.samples[0].t, T0);
    }

    #[test]
    fn pruning_drops_each_grain_past_its_own_retention() {
        let mut s = HistoryStore::open_in_memory().expect("mem");
        s.record(&rec(T0, &[("chrome", 2)])).expect("old sample");
        // Three days later: the minute is past 2 days, the hour and day are kept.
        s.record(&rec(T0 + 3 * DAY, &[("chrome", 1)])).expect("new sample");
        let all = |s: &HistoryStore, g: Grain| s.read(&q(0, u64::MAX / 2, g, g.ms())).expect("reads").samples.len();
        assert_eq!(all(&s, Grain::Minute), 1, "old minute pruned");
        assert_eq!(all(&s, Grain::Hour), 2);
        assert_eq!(all(&s, Grain::Day), 2);
        // Forty days later: old hours are gone too, days stay.
        s.prune(T0 + 40 * DAY).expect("prunes");
        assert_eq!(all(&s, Grain::Hour), 0);
        assert_eq!(all(&s, Grain::Day), 2);
    }

    #[test]
    fn a_failed_open_is_reported_by_every_command() {
        let state = HistoryState(std::sync::Mutex::new(Err("disk full".into())));
        assert_eq!(state.with(|s| s.schema()), Err("disk full".to_string()));
    }
}
