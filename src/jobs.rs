//! Background-job registry, backing `heisenberg://captures` and the `job.*`
//! control verbs. Long-running captures (Procmon now; WPR/TTD/ProcDump triggers
//! later) register here as jobs an agent can list, inspect, stop, and cancel.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::store;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum JobState {
    Running,
    Stopped,
    Failed,
    Cancelled,
}

impl JobState {
    fn is_terminal(self) -> bool {
        !matches!(self, JobState::Running)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    /// "procmon", later "wpr" / "ttd" / "procdump-trigger".
    pub kind: String,
    pub state: JobState,
    /// OS pid of the launched tool process (a launcher for some tools).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backing_file: Option<String>,
    pub summary: String,
    pub started: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stopped: Option<String>,
}

pub struct JobRegistry {
    path: PathBuf,
    jobs: Vec<Job>,
}

impl JobRegistry {
    pub fn load(path: PathBuf) -> JobRegistry {
        let jobs = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        JobRegistry { path, jobs }
    }

    fn save(&self) {
        if let Ok(bytes) = serde_json::to_vec_pretty(&self.jobs) {
            if let Err(e) = std::fs::write(&self.path, bytes) {
                tracing::warn!("job registry save failed: {e}");
            }
        }
    }

    pub fn add(
        &mut self,
        kind: &str,
        tool_pid: Option<u32>,
        backing_file: Option<String>,
        summary: &str,
    ) -> Job {
        let job = Job {
            id: format!("job-{}", chrono::Utc::now().format("%Y%m%dT%H%M%S%3fZ")),
            kind: kind.to_string(),
            state: JobState::Running,
            tool_pid,
            backing_file,
            summary: summary.to_string(),
            started: store::now_rfc3339(),
            stopped: None,
        };
        self.jobs.push(job.clone());
        self.save();
        job
    }

    pub fn get(&self, id: &str) -> Option<&Job> {
        self.jobs.iter().find(|j| j.id == id)
    }

    pub fn list(&self) -> &[Job] {
        &self.jobs
    }

    /// Transition a job. Terminal states stamp `stopped` if not already set.
    pub fn set_state(&mut self, id: &str, state: JobState) -> Option<Job> {
        let job = self.jobs.iter_mut().find(|j| j.id == id)?;
        job.state = state;
        if state.is_terminal() && job.stopped.is_none() {
            job.stopped = Some(store::now_rfc3339());
        }
        let out = job.clone();
        self.save();
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("hb_jobs_{tag}_{}.json", std::process::id()))
    }

    #[test]
    fn add_starts_running_then_stops() {
        let p = temp_path("add");
        let _ = std::fs::remove_file(&p);
        let mut r = JobRegistry::load(p.clone());
        let j = r.add("procmon", Some(123), Some("x.pml".into()), "capture");
        assert_eq!(j.state, JobState::Running);
        assert!(j.stopped.is_none());

        let updated = r.set_state(&j.id, JobState::Stopped).unwrap();
        assert_eq!(updated.state, JobState::Stopped);
        assert!(updated.stopped.is_some());
        assert_eq!(r.list().len(), 1);
        assert!(r.get(&j.id).is_some());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn persists_across_reload() {
        let p = temp_path("reload");
        let _ = std::fs::remove_file(&p);
        let id = {
            let mut r = JobRegistry::load(p.clone());
            r.add("procmon", None, None, "cap").id
        };
        let r2 = JobRegistry::load(p.clone());
        assert!(r2.get(&id).is_some());
        let _ = std::fs::remove_file(&p);
    }
}
