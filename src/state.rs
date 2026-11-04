use crate::model::*;
use anyhow::{anyhow, bail, Context, Result};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
    sync::Mutex,
};

/// Durable desired state. Kernel state is always reconstructed from this snapshot.
pub struct StateStore {
    db: Mutex<Connection>,
}
type InvitationRow = (
    String,
    Vec<u8>,
    i64,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<i64>,
    i64,
);

/// Shown when stored state was written by another RIFT version. RIFT keeps no compatibility
/// with older state formats.
pub const OLD_STATE: &str =
    "the stored RIFT state comes from a different RIFT version and cannot be read";

impl StateStore {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let db = Connection::open(path)
            .with_context(|| format!("open state database {}", path.display()))?;
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "synchronous", "FULL")?;
        db.execute_batch("PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS snapshot (id INTEGER PRIMARY KEY CHECK(id=1), generation INTEGER NOT NULL, body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS invites (name TEXT PRIMARY KEY, token_hash BLOB NOT NULL, expires_at INTEGER NOT NULL, reserved_agent TEXT, reserved_attempt TEXT, reserved_key TEXT, stage_deadline INTEGER, consumed INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS journal (seq INTEGER PRIMARY KEY AUTOINCREMENT, generation INTEGER NOT NULL, operation TEXT NOT NULL, created_at INTEGER NOT NULL, result TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS rotations (agent_id TEXT PRIMARY KEY, rotation_id TEXT NOT NULL, new_key TEXT, committed INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS applied (id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL, error TEXT);
            CREATE TABLE IF NOT EXISTS health (agent_id TEXT PRIMARY KEY, online INTEGER NOT NULL, last_disconnect INTEGER, last_handshake INTEGER NOT NULL);
            INSERT OR IGNORE INTO snapshot(id,generation,body) VALUES(1,0,'{\"generation\":0,\"agents\":[],\"forwards\":[],\"bans\":[],\"vpn_peers\":[],\"vpn_grants\":[]}');")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut p = std::fs::metadata(path)?.permissions();
            p.set_mode(0o600);
            std::fs::set_permissions(path, p)?;
            let wal = path.with_extension("db-wal");
            if wal.exists() {
                let mut p = std::fs::metadata(&wal)?.permissions();
                p.set_mode(0o600);
                std::fs::set_permissions(wal, p)?;
            }
        }
        Ok(Self { db: Mutex::new(db) })
    }
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.db.lock().map_err(|_| anyhow!("state lock poisoned"))
    }
    fn read_snapshot(c: &Connection) -> Result<StateSnapshot> {
        let body: String = c.query_row("SELECT body FROM snapshot WHERE id=1", [], |r| r.get(0))?;
        let snapshot: StateSnapshot = serde_json::from_str(&body).map_err(|e| {
            anyhow!(
                "{OLD_STATE} (state.db: {e}). On the server: remove it with `docker compose \
                 down -v`, start again and set it up anew, or restore a backup made by this \
                 version"
            )
        })?;
        validate_snapshot(&snapshot)?;
        Ok(snapshot)
    }
    pub fn snapshot(&self) -> Result<StateSnapshot> {
        let c = self.lock()?;
        Self::read_snapshot(&c)
    }
    pub fn observe_health(&self, peers: &[PeerStats], timeout: u64) -> Result<()> {
        let mut c = self.lock()?;
        let tx = c.transaction()?;
        let snapshot = Self::read_snapshot(&tx)?;
        for agent in &snapshot.agents {
            let handshake = peers
                .iter()
                .find(|p| p.public_key == agent.public_key)
                .map(|p| p.last_handshake)
                .unwrap_or(0);
            let online = agent.status == AgentStatus::Active
                && handshake > 0
                && now().saturating_sub(handshake) <= timeout as i64;
            tx.execute("INSERT INTO health(agent_id,online,last_disconnect,last_handshake) VALUES(?1,?2,NULL,?3) ON CONFLICT(agent_id) DO UPDATE SET last_disconnect=CASE WHEN health.online=1 AND excluded.online=0 THEN ?4 ELSE health.last_disconnect END,online=excluded.online,last_handshake=MAX(health.last_handshake,excluded.last_handshake)",params![agent.id,online,handshake,now()])?;
        }
        tx.commit()?;
        Ok(())
    }
    pub fn health(&self) -> Result<Vec<serde_json::Value>> {
        let c = self.lock()?;
        let mut query=c.prepare("SELECT agent_id,online,last_disconnect,last_handshake FROM health WHERE agent_id IN (SELECT value->>'id' FROM json_each((SELECT body FROM snapshot WHERE id=1),'$.agents'))")?;
        let values=query.query_map([],|row|Ok(serde_json::json!({"agent_id":row.get::<_,String>(0)?,"online":row.get::<_,bool>(1)?,"last_observed_disconnect":row.get::<_,Option<i64>>(2)?,"last_handshake":row.get::<_,i64>(3)?})))?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(values)
    }
    pub fn last_applied(&self) -> Result<Option<StateSnapshot>> {
        let c = self.lock()?;
        let body: Option<String> = c
            .query_row("SELECT body FROM applied WHERE id=1", [], |row| row.get(0))
            .optional()?;
        body.map(|body| serde_json::from_str(&body).map_err(Into::into))
            .transpose()
    }
    pub fn mark_applied(&self, snapshot: &StateSnapshot) -> Result<()> {
        let c = self.lock()?;
        let body = serde_json::to_string(snapshot)?;
        c.execute("INSERT INTO applied(id,body,error) VALUES(1,?1,NULL) ON CONFLICT(id) DO UPDATE SET body=excluded.body,error=NULL WHERE applied.body!=excluded.body OR applied.error IS NOT NULL", [&body])?;
        c.execute(
            "UPDATE journal SET result='applied' WHERE generation=?1 AND result='committed'",
            [snapshot.generation as i64],
        )?;
        Ok(())
    }
    pub fn mark_failed(&self, generation: u64, error: &str) -> Result<()> {
        let c = self.lock()?;
        c.execute("UPDATE applied SET error=?1 WHERE id=1", [error])?;
        c.execute(
            "UPDATE journal SET result=?1 WHERE generation=?2",
            params![format!("failed: {error}"), generation as i64],
        )?;
        Ok(())
    }
    pub fn apply_error(&self) -> Result<Option<String>> {
        let c = self.lock()?;
        Ok(
            c.query_row("SELECT error FROM applied WHERE id=1", [], |row| row.get(0))
                .optional()?
                .flatten(),
        )
    }
    fn commit_snapshot(
        tx: &Transaction<'_>,
        mut s: StateSnapshot,
        op: &str,
    ) -> Result<StateSnapshot> {
        validate_snapshot(&s)?;
        s.generation = s.generation.saturating_add(1);
        let json = serde_json::to_string(&s)?;
        tx.execute(
            "UPDATE snapshot SET generation=?1,body=?2 WHERE id=1",
            params![s.generation as i64, json],
        )?;
        tx.execute("INSERT INTO journal(generation,operation,created_at,result) VALUES(?1,?2,?3,'committed')", params![s.generation as i64, op, now()])?;
        Ok(s)
    }
    pub fn invite(&self, name: &str, token_hash: &[u8], expires_at: i64) -> Result<()> {
        let mut c = self.lock()?;
        let tx = c.transaction()?;
        let generation = Self::read_snapshot(&tx)?.generation;
        tx.execute(
            "DELETE FROM invites WHERE name=?1 AND (consumed=1 OR expires_at<?2)",
            params![name, now()],
        )?;
        tx.execute(
            "INSERT INTO invites(name,token_hash,expires_at) VALUES(?1,?2,?3)",
            params![name, token_hash, expires_at],
        )
        .context("invitation name already exists")?;
        tx.execute("INSERT INTO journal(generation,operation,created_at,result) VALUES(?1,'invite-create',?2,'committed')",params![generation as i64,now()])?;
        tx.commit()?;
        Ok(())
    }
    pub fn cancel_invite(&self, name: &str) -> Result<StateSnapshot> {
        let mut c = self.lock()?;
        let tx = c.transaction()?;
        let mut s = Self::read_snapshot(&tx)?;
        let pending: Vec<String> = {
            let mut q = tx.prepare(
                "SELECT reserved_agent FROM invites WHERE name=?1 AND reserved_agent IS NOT NULL AND consumed=0",
            )?;
            let rows = q.query_map([name], |r| r.get(0))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        s.agents.retain(|a| !pending.contains(&a.id));
        tx.execute("DELETE FROM invites WHERE name=?1", [name])?;
        if pending.is_empty() {
            tx.execute("INSERT INTO journal(generation,operation,created_at,result) VALUES(?1,'invite-cancel',?2,'committed')",params![s.generation as i64,now()])?;
            tx.commit()?;
            return Ok(s);
        }
        let out = Self::commit_snapshot(&tx, s, "invite-cancel")?;
        tx.commit()?;
        Ok(out)
    }
    /// Reserve the invitation and addresses atomically. Replaying the same attempt returns the same record.
    #[allow(clippy::too_many_arguments)] // One atomic enrollment transaction includes both address families.
    pub fn reserve_enrollment(
        &self,
        token_hash: &[u8],
        name: &str,
        id: &str,
        attempt: &str,
        key: &str,
        v4_pool: ipnet::Ipv4Net,
        v6_pool: ipnet::Ipv6Net,
        server4: Ipv4Addr,
        server6: Ipv6Addr,
        stage_seconds: i64,
    ) -> Result<AgentRecord> {
        let mut c = self.lock()?;
        let tx = c.transaction()?;
        let mut s = Self::read_snapshot(&tx)?;
        let inv: Option<InvitationRow> = tx.query_row(
            "SELECT name,token_hash,expires_at,reserved_agent,reserved_attempt,reserved_key,stage_deadline,consumed FROM invites WHERE token_hash=?1", [token_hash],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?))).optional()?;
        let Some((
            invite_name,
            stored,
            expires,
            reserved_agent,
            reserved_attempt,
            reserved_key,
            deadline,
            consumed,
        )) = inv
        else {
            bail!("invalid invitation")
        };
        if stored != token_hash || consumed != 0 || expires < now() {
            bail!("invitation is expired or already used")
        }
        if invite_name != name {
            bail!("invitation is restricted to a different agent name")
        }
        // Re-enrollment of an existing agent: the agent keeps its ID, addresses and everything
        // that refers to it; only key and attempt change. The new install learns the ID from
        // the welcome. Retries of the same attempt return the same record.
        if let Some(index) = s
            .agents
            .iter()
            .position(|a| a.name == name && a.status != AgentStatus::Pending)
        {
            let existing = s.agents[index].clone();
            if let Some(reserved) = reserved_agent {
                if reserved != existing.id
                    || reserved_attempt.as_deref() != Some(attempt)
                    || reserved_key.as_deref() != Some(key)
                    || deadline.unwrap_or_default() < now()
                {
                    bail!("invitation is reserved by another or expired attempt")
                }
                tx.commit()?;
                return Ok(existing);
            }
            anyhow::ensure!(
                existing.status == AgentStatus::Active,
                "only an active agent can be enrolled again"
            );
            anyhow::ensure!(
                !s.agents.iter().any(|a| a.public_key == key),
                "this WireGuard key is already in use"
            );
            let stage_deadline = (now() + stage_seconds).min(expires);
            let generation = s.generation + 1;
            let agent = &mut s.agents[index];
            agent.public_key = key.into();
            agent.attempt_id = attempt.into();
            agent.generation = generation;
            agent.applied_generation = 0;
            agent.last_error = None;
            let record = agent.clone();
            tx.execute("DELETE FROM rotations WHERE agent_id=?1", [&record.id])?;
            tx.execute("UPDATE invites SET reserved_agent=?1,reserved_attempt=?2,reserved_key=?3,stage_deadline=?4 WHERE token_hash=?5", params![record.id,attempt,key,stage_deadline,token_hash])?;
            Self::commit_snapshot(&tx, s, "enrollment-replace")?;
            tx.commit()?;
            return Ok(record);
        }
        if let Some(a) = s
            .agents
            .iter()
            .find(|a| a.id == id || a.attempt_id == attempt)
        {
            if a.status == AgentStatus::Active {
                bail!("active enrollment cannot be replayed over TLS")
            }
            ensure_same_enrollment(a, id, name, attempt, key)?;
            if reserved_agent.as_deref() != Some(id)
                || reserved_attempt.as_deref() != Some(attempt)
                || reserved_key.as_deref() != Some(key)
                || deadline.unwrap_or_default() < now()
            {
                bail!("attempt is not reserved by this live invitation")
            }
            tx.commit()?;
            return Ok(a.clone());
        }
        if let Some(ra) = reserved_agent {
            if reserved_attempt.as_deref() != Some(attempt)
                || reserved_key.as_deref() != Some(key)
                || deadline.unwrap_or_default() < now()
            {
                bail!("invitation is reserved by another or expired attempt")
            }
            let a = s
                .agents
                .iter()
                .find(|a| a.id == ra)
                .ok_or_else(|| anyhow!("orphaned invitation reservation"))?;
            ensure_same_enrollment(a, id, name, attempt, key)?;
            tx.commit()?;
            return Ok(a.clone());
        }
        let ip4 = allocate_v4(v4_pool, server4, &s.agents)?;
        let ip6 = allocate_v6(v6_pool, server6, &s.agents)?;
        let t = now();
        let stage_deadline = (t + stage_seconds).min(expires);
        let record = AgentRecord {
            id: id.into(),
            name: name.into(),
            public_key: key.into(),
            tunnel_ipv4: ip4,
            tunnel_ipv6: ip6,
            status: AgentStatus::Pending,
            attempt_id: attempt.into(),
            generation: s.generation + 1,
            applied_generation: 0,
            last_error: None,
            created_at: t,
            pending_deadline: Some(stage_deadline),
            limits: None,
            exit: None,
            exit_port: None,
        };
        s.agents.push(record.clone());
        tx.execute("UPDATE invites SET reserved_agent=?1,reserved_attempt=?2,reserved_key=?3,stage_deadline=?4 WHERE token_hash=?5", params![id,attempt,key,stage_deadline,token_hash])?;
        Self::commit_snapshot(&tx, s, "enrollment-reserve")?;
        tx.commit()?;
        Ok(record)
    }
    /// The ACK arrives only over WireGuard, after proving possession of the reserved key.
    pub fn activate(&self, id: &str, attempt: &str, source: IpAddr) -> Result<StateSnapshot> {
        let mut c = self.lock()?;
        let tx = c.transaction()?;
        let mut s = Self::read_snapshot(&tx)?;
        let generation = s.generation + 1;
        let a = s
            .agents
            .iter_mut()
            .find(|a| a.id == id)
            .ok_or_else(|| anyhow!("unknown agent"))?;
        if a.attempt_id != attempt
            || (source != IpAddr::V4(a.tunnel_ipv4) && source != IpAddr::V6(a.tunnel_ipv6))
        {
            bail!("activation identity or tunnel source mismatch")
        }
        if a.status == AgentStatus::Active {
            // A re-enrolled agent was active all along; its invitation is used up now.
            tx.execute(
                "UPDATE invites SET consumed=1 WHERE reserved_agent=?1 AND reserved_attempt=?2",
                params![id, attempt],
            )?;
            tx.commit()?;
            return Ok(s);
        }
        if a.status != AgentStatus::Pending || a.pending_deadline.unwrap_or_default() < now() {
            bail!("staging enrollment expired")
        }
        let valid:i64=tx.query_row("SELECT COUNT(*) FROM invites WHERE reserved_agent=?1 AND reserved_attempt=?2 AND consumed=0 AND expires_at>=?3 AND stage_deadline>=?3",params![id,attempt,now()],|r|r.get(0))?;
        if valid != 1 {
            bail!("enrollment invitation expired or was revoked")
        }
        a.status = AgentStatus::Active;
        a.pending_deadline = None;
        a.generation = generation;
        let updated = Self::commit_snapshot(&tx, s, "enrollment-activate")?;
        tx.execute(
            "UPDATE invites SET consumed=1 WHERE reserved_agent=?1",
            [id],
        )?;
        tx.commit()?;
        Ok(updated)
    }
    pub fn expire_staging(&self) -> Result<StateSnapshot> {
        let mut c = self.lock()?;
        let tx = c.transaction()?;
        let mut s = Self::read_snapshot(&tx)?;
        let t = now();
        let old_bans = s.bans.len();
        s.bans.retain(|ban| ban.expires_at > t);
        let deleted_invites = tx.execute("DELETE FROM invites WHERE expires_at<?1", [t])?;
        let expired: Vec<String> = s
            .agents
            .iter()
            .filter(|a| {
                a.status == AgentStatus::Pending && a.pending_deadline.unwrap_or_default() < t
            })
            .map(|a| a.id.clone())
            .collect();
        if expired.is_empty() && old_bans == s.bans.len() {
            if deleted_invites > 0 {
                tx.execute("INSERT INTO journal(generation,operation,created_at,result) VALUES(?1,'invite-expire',?2,'committed')",params![s.generation as i64,t])?;
            }
            tx.commit()?;
            return Ok(s);
        }
        s.agents.retain(|a| !expired.contains(&a.id));
        for id in expired {
            tx.execute("UPDATE invites SET reserved_agent=NULL,reserved_attempt=NULL,reserved_key=NULL,stage_deadline=NULL WHERE reserved_agent=?1 AND expires_at>=?2", params![id,t])?;
            tx.execute("DELETE FROM invites WHERE reserved_agent=?1", [&id])?;
        }
        let updated = Self::commit_snapshot(&tx, s, "staging-expire")?;
        tx.commit()?;
        Ok(updated)
    }
    pub fn agent_by_id(&self, id: &str) -> Result<Option<AgentRecord>> {
        Ok(self.snapshot()?.agents.into_iter().find(|a| a.id == id))
    }
    pub fn update_agent_sync(
        &self,
        id: &str,
        applied: u64,
        error: Option<String>,
        limits: AgentLimits,
        exit: Option<ExitReport>,
    ) -> Result<StateSnapshot> {
        let mut c = self.lock()?;
        let tx = c.transaction()?;
        let mut s = Self::read_snapshot(&tx)?;
        anyhow::ensure!(
            applied <= s.generation,
            "agent cannot acknowledge a future generation"
        );
        let error = error.map(|value| value.chars().take(300).collect::<String>());
        let changed = {
            let a = s
                .agents
                .iter_mut()
                .find(|a| a.id == id)
                .ok_or_else(|| anyhow!("unknown agent"))?;
            let changed = a.applied_generation != applied
                || a.last_error != error
                || a.limits.as_ref() != Some(&limits)
                || a.exit != exit;
            if changed {
                a.applied_generation = applied;
                a.last_error = error;
                a.limits = Some(limits);
                a.exit = exit;
            }
            changed
        };
        if changed {
            let generation = s.generation;
            let json = serde_json::to_string(&s)?;
            tx.execute("UPDATE snapshot SET body=?1 WHERE id=1", [json])?;
            tx.execute("INSERT INTO journal(generation,operation,created_at,result) VALUES(?1,'agent-sync',?2,'committed')",params![generation as i64,now()])?;
        }
        tx.commit()?;
        Ok(s)
    }
    pub fn request_rotation(&self, id: &str, rotation_id: &str) -> Result<()> {
        let mut c = self.lock()?;
        let tx = c.transaction()?;
        let s = Self::read_snapshot(&tx)?;
        if !s
            .agents
            .iter()
            .any(|a| a.id == id && a.status == AgentStatus::Active)
        {
            bail!("only active agents can begin key rotation")
        }
        let pending: i64 = tx.query_row(
            "SELECT COUNT(*) FROM rotations WHERE agent_id=?1 AND committed=0",
            [id],
            |r| r.get(0),
        )?;
        if pending > 0 {
            bail!("an agent key rotation is already pending")
        }
        tx.execute("INSERT INTO rotations(agent_id,rotation_id,new_key,committed) VALUES(?1,?2,NULL,0) ON CONFLICT(agent_id) DO UPDATE SET rotation_id=excluded.rotation_id,new_key=NULL,committed=0",params![id,rotation_id])?;
        tx.execute("INSERT INTO journal(generation,operation,created_at,result) VALUES(?1,'agent-rotate-request',?2,'committed')",params![s.generation as i64,now()])?;
        tx.commit()?;
        Ok(())
    }
    pub fn rotation(&self, id: &str) -> Result<Option<(String, Option<String>, bool)>> {
        let c = self.lock()?;
        Ok(c.query_row(
            "SELECT rotation_id,new_key,committed FROM rotations WHERE agent_id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)? != 0)),
        )
        .optional()?)
    }
    pub fn commit_rotation(
        &self,
        id: &str,
        rotation_id: &str,
        new_key: &str,
    ) -> Result<StateSnapshot> {
        let mut c = self.lock()?;
        let tx = c.transaction()?;
        let existing: Option<(String, Option<String>, i64)> = tx
            .query_row(
                "SELECT rotation_id,new_key,committed FROM rotations WHERE agent_id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        if let Some((rid, Some(key), 1)) = existing.as_ref() {
            if rid == rotation_id && key == new_key {
                tx.commit()?;
                return Self::read_snapshot(&c);
            }
            bail!("committed rotation cannot be rebound to another key");
        }
        if existing.as_ref().map(|x| x.0.as_str()) != Some(rotation_id) {
            bail!("rotation is not pending")
        }
        let mut s = Self::read_snapshot(&tx)?;
        if s.agents
            .iter()
            .any(|x| x.id != id && x.public_key == new_key)
        {
            bail!("new WireGuard key is already assigned")
        }
        let generation = s.generation + 1;
        let a = s
            .agents
            .iter_mut()
            .find(|a| a.id == id)
            .ok_or_else(|| anyhow!("unknown agent"))?;
        a.public_key = new_key.into();
        a.generation = generation;
        let out = Self::commit_snapshot(&tx, s, "agent-rotate")?;
        tx.execute(
            "UPDATE rotations SET new_key=?1,committed=1 WHERE agent_id=?2 AND rotation_id=?3",
            params![new_key, id, rotation_id],
        )?;
        tx.commit()?;
        Ok(out)
    }
    pub fn mutate(
        &self,
        op: &str,
        f: impl FnOnce(&mut StateSnapshot) -> Result<()>,
    ) -> Result<StateSnapshot> {
        let mut c = self.lock()?;
        let tx = c.transaction()?;
        let mut s = Self::read_snapshot(&tx)?;
        f(&mut s)?;
        let out = Self::commit_snapshot(&tx, s, op)?;
        tx.commit()?;
        Ok(out)
    }
    pub fn remove_agent(&self, id: &str) -> Result<StateSnapshot> {
        let mut c = self.lock()?;
        let tx = c.transaction()?;
        let mut s = Self::read_snapshot(&tx)?;
        anyhow::ensure!(s.agents.iter().any(|a| a.id == id), "agent not found");
        s.agents.retain(|a| a.id != id);
        s.forwards.retain(|f| f.agent_id != id);
        s.bans.retain(|b| b.agent_id != id);
        s.vpn_grants.retain(|g| g.agent_id != id);
        for peer in &mut s.vpn_peers {
            peer.agent_exits.retain(|x| x != id);
        }
        tx.execute("DELETE FROM invites WHERE reserved_agent=?1", [id])?;
        tx.execute("DELETE FROM rotations WHERE agent_id=?1", [id])?;
        let out = Self::commit_snapshot(&tx, s, "agent-remove")?;
        tx.commit()?;
        Ok(out)
    }
    pub fn invites(&self) -> Result<Vec<(String, i64, bool)>> {
        let c = self.lock()?;
        let mut st = c.prepare("SELECT name,expires_at,consumed FROM invites ORDER BY name")?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)? != 0)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
    /// Invitations that can still be used or are being used: the enrollment port must listen.
    pub fn open_invites(&self) -> Result<Vec<(String, i64)>> {
        let c = self.lock()?;
        let mut st = c.prepare(
            "SELECT name,expires_at FROM invites WHERE consumed=0 AND expires_at>=?1 ORDER BY expires_at",
        )?;
        let rows = st.query_map([now()], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
    pub fn invite_hash(token: &str) -> Vec<u8> {
        Sha256::digest(token.as_bytes()).to_vec()
    }
}

fn ensure_same_enrollment(
    a: &AgentRecord,
    id: &str,
    name: &str,
    attempt: &str,
    key: &str,
) -> Result<()> {
    if a.id != id || a.name != name || a.attempt_id != attempt || a.public_key != key {
        bail!("attempt ID is already bound to different enrollment data")
    };
    Ok(())
}
fn validate_snapshot(s: &StateSnapshot) -> Result<()> {
    anyhow::ensure!(
        s.bans.len() <= 8192,
        "maximum number of scoped bans reached"
    );
    let (mut ids, mut names, mut keys, mut v4, mut v6, mut attempts) = (
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
    );
    for a in &s.agents {
        anyhow::ensure!(ids.insert(&a.id), "duplicate agent ID");
        anyhow::ensure!(names.insert(&a.name), "duplicate agent name");
        anyhow::ensure!(keys.insert(&a.public_key), "duplicate WireGuard public key");
        anyhow::ensure!(v4.insert(a.tunnel_ipv4), "duplicate agent IPv4 address");
        anyhow::ensure!(v6.insert(a.tunnel_ipv6), "duplicate agent IPv6 address");
        anyhow::ensure!(
            attempts.insert(&a.attempt_id),
            "duplicate enrollment attempt ID"
        );
    }
    let mut forward_ids = HashSet::new();
    for f in &s.forwards {
        f.validate()?;
        anyhow::ensure!(forward_ids.insert(f.id), "duplicate forward ID");
        anyhow::ensure!(
            ids.contains(&f.agent_id),
            "forward references unknown agent"
        );
    }
    for (i, a) in s.forwards.iter().enumerate() {
        for b in s.forwards.iter().skip(i + 1) {
            if a.listen_ip == b.listen_ip
                && a.protocol == b.protocol
                && a.listen_ports.overlaps(b.listen_ports)
            {
                bail!("public port ranges overlap, including disabled forwards")
            }
        }
    }
    let (mut peer_names, mut peer_ips, mut peer_ips6) =
        (HashSet::new(), HashSet::new(), HashSet::new());
    let mut exit_ports = HashSet::new();
    for a in &s.agents {
        if let Some(port) = a.exit_port {
            anyhow::ensure!(exit_ports.insert(port), "duplicate exit port");
        }
    }
    for p in &s.vpn_peers {
        crate::config::validate_name(&p.name)?;
        anyhow::ensure!(peer_names.insert(&p.name), "duplicate VPN peer name");
        anyhow::ensure!(peer_ips.insert(p.ipv4), "duplicate VPN peer address");
        anyhow::ensure!(peer_ips6.insert(p.ipv6), "duplicate VPN peer IPv6 address");
        let mut exits = HashSet::new();
        for id in &p.agent_exits {
            anyhow::ensure!(ids.contains(id), "VPN peer exit references unknown agent");
            anyhow::ensure!(exits.insert(id), "VPN peer lists an agent exit twice");
        }
        anyhow::ensure!(
            keys.insert(&p.public_key),
            "VPN peer reuses a WireGuard public key"
        );
    }
    for (i, g) in s.vpn_grants.iter().enumerate() {
        anyhow::ensure!(
            peer_names.contains(&g.peer),
            "VPN grant references unknown peer"
        );
        anyhow::ensure!(
            ids.contains(&g.agent_id),
            "VPN grant references unknown agent"
        );
        crate::vpn::validate_access(&g.access)?;
        anyhow::ensure!(!s.vpn_grants[..i].contains(g), "duplicate VPN grant");
        anyhow::ensure!(
            g.access != VpnAccess::Dns
                || !s.vpn_grants[..i]
                    .iter()
                    .any(|o| o.peer == g.peer && o.access == VpnAccess::Dns),
            "device {} has more than one DNS server",
            g.peer
        );
        // One network behind two agents would make the VPS route ambiguous.
        if let VpnAccess::Subnet { net, .. } = &g.access {
            for other in &s.vpn_grants[..i] {
                if let VpnAccess::Subnet { net: o, .. } = &other.access {
                    anyhow::ensure!(
                        other.agent_id == g.agent_id || !(net.contains(o) || o.contains(net)),
                        "subnet {net} overlaps {o}, which is granted behind a different agent"
                    );
                }
            }
        }
    }
    let mut ban_ids = HashSet::new();
    for b in &s.bans {
        anyhow::ensure!(ban_ids.insert(b.id), "duplicate ban ID");
        anyhow::ensure!(
            ids.contains(&b.agent_id) && forward_ids.contains(&b.forward_id),
            "ban references unknown agent or forward"
        );
    }
    Ok(())
}
fn allocate_v4(pool: ipnet::Ipv4Net, server: Ipv4Addr, agents: &[AgentRecord]) -> Result<Ipv4Addr> {
    for x in pool.hosts() {
        if x != server && !agents.iter().any(|a| a.tunnel_ipv4 == x) {
            return Ok(x);
        }
    }
    bail!("IPv4 tunnel pool is exhausted")
}
fn allocate_v6(pool: ipnet::Ipv6Net, server: Ipv6Addr, agents: &[AgentRecord]) -> Result<Ipv6Addr> {
    let start = u128::from(pool.network());
    let end = u128::from(pool.broadcast());
    let mut n = start.saturating_add(1);
    while n < end && n - start < 1_000_000 {
        let x = Ipv6Addr::from(n);
        if x != server && !agents.iter().any(|a| a.tunnel_ipv6 == x) {
            return Ok(x);
        }
        n += 1;
    }
    bail!("IPv6 tunnel pool exhausted or too large to scan")
}

/// The smallest positive ID not in use, so IDs freed by a removal are handed out again.
pub fn lowest_free_id(used: impl IntoIterator<Item = u64>) -> u64 {
    let used: HashSet<u64> = used.into_iter().collect();
    (1..).find(|id| !used.contains(id)).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    #[test]
    fn vpn_state_is_validated() {
        let agent = |id: &str, n: u8| AgentRecord {
            id: id.into(),
            name: id.into(),
            public_key: format!("k-{id}"),
            tunnel_ipv4: Ipv4Addr::new(10, 13, 0, n),
            tunnel_ipv6: Ipv6Addr::new(0xfd88, 0x5249, 0x4654, 0, 0, 0, 0, n.into()),
            status: AgentStatus::Active,
            attempt_id: id.into(),
            generation: 1,
            applied_generation: 1,
            last_error: None,
            created_at: 0,
            pending_deadline: None,
            limits: None,
            exit: None,
            exit_port: None,
        };
        let subnet = |net: &str| VpnAccess::Subnet {
            net: net.parse().unwrap(),
            snat: false,
        };
        let peer = VpnPeer {
            name: "iphone".into(),
            public_key: "k-iphone".into(),
            ipv4: Ipv4Addr::new(10, 14, 0, 2),
            enabled: true,
            created_at: 0,
            panel: false,
            server_exit: false,
            agent_exits: Vec::new(),
            ipv6: std::net::Ipv6Addr::LOCALHOST,
        };
        let grant = |agent: &str, access| VpnGrant {
            peer: "iphone".into(),
            agent_id: agent.into(),
            access,
        };
        let base = StateSnapshot {
            agents: vec![agent("a", 2), agent("b", 3)],
            vpn_peers: vec![peer.clone()],
            vpn_grants: vec![grant("a", subnet("192.168.178.0/24"))],
            ..Default::default()
        };
        validate_snapshot(&base).unwrap();
        let mut s = base.clone();
        s.vpn_grants.push(grant("a", subnet("192.168.178.0/25")));
        validate_snapshot(&s).unwrap();
        s.vpn_grants.push(grant("b", subnet("192.168.178.128/25")));
        assert!(validate_snapshot(&s).is_err(), "same LAN behind two agents");
        let mut s = base.clone();
        s.vpn_grants.push(grant("zzz", VpnAccess::Server));
        assert!(validate_snapshot(&s).is_err(), "unknown agent");
        let mut s = base.clone();
        s.vpn_grants.push(grant("a", subnet("192.168.178.0/24")));
        assert!(validate_snapshot(&s).is_err(), "duplicate grant");
        let mut s = base.clone();
        s.vpn_peers.push(VpnPeer {
            name: "other".into(),
            ..peer.clone()
        });
        assert!(validate_snapshot(&s).is_err(), "duplicate address and key");
        let mut s = base.clone();
        s.vpn_peers[0].public_key = "k-a".into();
        assert!(validate_snapshot(&s).is_err(), "key shared with an agent");
        let mut s = base.clone();
        s.vpn_grants.push(grant("a", VpnAccess::Dns));
        validate_snapshot(&s).unwrap();
        s.vpn_grants.push(grant("b", VpnAccess::Dns));
        assert!(validate_snapshot(&s).is_err(), "two DNS servers");
    }
    #[test]
    fn exits_are_validated_and_follow_their_agent() {
        let store = StateStore::open(&tempdir().unwrap().path().join("s.db")).unwrap();
        let agent = |id: &str, n: u8, port: Option<u16>| AgentRecord {
            id: id.into(),
            name: id.into(),
            public_key: format!("k-{id}"),
            tunnel_ipv4: Ipv4Addr::new(10, 13, 0, n),
            tunnel_ipv6: Ipv6Addr::new(0xfd88, 0x5249, 0x4654, 0, 0, 0, 0, n.into()),
            status: AgentStatus::Active,
            attempt_id: id.into(),
            generation: 1,
            applied_generation: 1,
            last_error: None,
            created_at: 0,
            pending_deadline: None,
            limits: None,
            exit: None,
            exit_port: port,
        };
        let device = |name: &str, n: u8, agent_exits: Vec<String>| VpnPeer {
            name: name.into(),
            public_key: format!("k-{name}"),
            ipv4: Ipv4Addr::new(10, 14, 0, n),
            enabled: true,
            created_at: 0,
            panel: false,
            ipv6: Ipv6Addr::new(0xfd88, 0x5249, 0x4655, 0, 0, 0, 0, n.into()),
            server_exit: false,
            agent_exits,
        };
        let base = StateSnapshot {
            agents: vec![agent("a", 2, Some(51821)), agent("b", 3, Some(51822))],
            vpn_peers: vec![device("phone", 2, vec!["a".into()])],
            ..Default::default()
        };
        validate_snapshot(&base).unwrap();
        let mut s = base.clone();
        s.vpn_peers[0].agent_exits = vec!["zzz".into()];
        assert!(validate_snapshot(&s).is_err(), "unknown exit agent");
        let mut s = base.clone();
        s.vpn_peers[0].agent_exits = vec!["a".into(), "a".into()];
        assert!(validate_snapshot(&s).is_err(), "the same exit twice");
        let mut s = base.clone();
        s.vpn_peers[0].agent_exits = vec!["a".into(), "b".into()];
        validate_snapshot(&s).unwrap();
        let mut s = base.clone();
        s.agents[1].exit_port = Some(51821);
        assert!(
            validate_snapshot(&s).is_err(),
            "one exit port for two agents"
        );
        let mut s = base.clone();
        s.vpn_peers.push(device("tablet", 3, vec![]));
        s.vpn_peers[1].ipv6 = s.vpn_peers[0].ipv6;
        assert!(
            validate_snapshot(&s).is_err(),
            "duplicate device IPv6 address"
        );
        // Removing the agent leaves the device without an exit.
        store
            .mutate("seed", |x| {
                *x = base.clone();
                Ok(())
            })
            .unwrap();
        let after = store.remove_agent("a").unwrap();
        assert!(after.vpn_peers[0].agent_exits.is_empty());
    }

    #[test]
    fn state_from_another_version_says_what_to_do() {
        let d = tempdir().unwrap();
        let path = d.path().join("state.db");
        StateStore::open(&path).unwrap();
        let c = Connection::open(&path).unwrap();
        c.execute(
            "UPDATE snapshot SET body='{\"generation\":1,\"agents\":[],\"forwards\":[],\"bans\":[]}' WHERE id=1",
            [],
        )
        .unwrap();
        let error = StateStore::open(&path)
            .unwrap()
            .snapshot()
            .unwrap_err()
            .to_string();
        assert!(error.contains("different RIFT version"), "{error}");
        assert!(error.contains("docker compose down -v"), "{error}");
    }
    #[test]
    fn forward_ids_fill_gaps_before_growing() {
        assert_eq!(lowest_free_id([]), 1);
        assert_eq!(lowest_free_id([1, 2, 3]), 4);
        assert_eq!(lowest_free_id([1, 2, 4, 5, 7]), 3);
        assert_eq!(lowest_free_id([2, 3]), 1);
    }
    #[test]
    fn invitation_reservation_is_idempotent_and_single_use() {
        let d = tempdir().unwrap();
        let st = StateStore::open(&d.path().join("state.db")).unwrap();
        let h = StateStore::invite_hash("high-entropy-token");
        st.invite("agent", &h, now() + 600).unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let attempt = uuid::Uuid::new_v4().to_string();
        let pool4 = "10.4.0.0/24".parse().unwrap();
        let pool6 = "fd00:4::/64".parse().unwrap();
        let a = st
            .reserve_enrollment(
                &h,
                "agent",
                &id,
                &attempt,
                "pubkey",
                pool4,
                pool6,
                "10.4.0.1".parse().unwrap(),
                "fd00:4::1".parse().unwrap(),
                120,
            )
            .unwrap();
        let b = st
            .reserve_enrollment(
                &h,
                "agent",
                &id,
                &attempt,
                "pubkey",
                pool4,
                pool6,
                "10.4.0.1".parse().unwrap(),
                "fd00:4::1".parse().unwrap(),
                120,
            )
            .unwrap();
        assert_eq!(a.id, b.id);
        assert_eq!(st.snapshot().unwrap().agents.len(), 1);
        assert!(st
            .reserve_enrollment(
                &StateStore::invite_hash("wrong-token"),
                "agent",
                &id,
                &attempt,
                "pubkey",
                pool4,
                pool6,
                "10.4.0.1".parse().unwrap(),
                "fd00:4::1".parse().unwrap(),
                120
            )
            .is_err());
        assert!(st
            .reserve_enrollment(
                &h,
                "other",
                &uuid::Uuid::new_v4().to_string(),
                &uuid::Uuid::new_v4().to_string(),
                "otherkey",
                pool4,
                pool6,
                "10.4.0.1".parse().unwrap(),
                "fd00:4::1".parse().unwrap(),
                120
            )
            .is_err());
    }
    #[test]
    fn activation_requires_reserved_tunnel_address() {
        let d = tempdir().unwrap();
        let st = StateStore::open(&d.path().join("state.db")).unwrap();
        let h = StateStore::invite_hash("token");
        st.invite("a", &h, now() + 600).unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let at = uuid::Uuid::new_v4().to_string();
        st.reserve_enrollment(
            &h,
            "a",
            &id,
            &at,
            "k",
            "10.5.0.0/24".parse().unwrap(),
            "fd00:5::/64".parse().unwrap(),
            "10.5.0.1".parse().unwrap(),
            "fd00:5::1".parse().unwrap(),
            120,
        )
        .unwrap();
        assert!(st.activate(&id, &at, "10.5.0.99".parse().unwrap()).is_err());
        assert_eq!(
            st.activate(&id, &at, "10.5.0.2".parse().unwrap())
                .unwrap()
                .agents[0]
                .status,
            AgentStatus::Active
        );
    }
    #[test]
    fn an_invitation_keeps_enrollment_open_until_activation_or_expiry() {
        let d = tempdir().unwrap();
        let st = StateStore::open(&d.path().join("state.db")).unwrap();
        assert!(st.open_invites().unwrap().is_empty());
        let h = StateStore::invite_hash("token");
        st.invite("agent", &h, now() + 600).unwrap();
        st.invite("late", &StateStore::invite_hash("old"), now() - 1)
            .unwrap();
        let open: Vec<_> = st
            .open_invites()
            .unwrap()
            .into_iter()
            .map(|i| i.0)
            .collect();
        assert_eq!(open, ["agent"], "an expired invitation does not count");
        let id = uuid::Uuid::new_v4().to_string();
        let attempt = uuid::Uuid::new_v4().to_string();
        st.reserve_enrollment(
            &h,
            "agent",
            &id,
            &attempt,
            "k",
            "10.6.0.0/24".parse().unwrap(),
            "fd00:6::/64".parse().unwrap(),
            "10.6.0.1".parse().unwrap(),
            "fd00:6::1".parse().unwrap(),
            120,
        )
        .unwrap();
        // A reserved token may still be retried, so the port stays open until activation.
        assert_eq!(st.open_invites().unwrap().len(), 1);
        st.activate(&id, &attempt, "10.6.0.2".parse().unwrap())
            .unwrap();
        assert!(st.open_invites().unwrap().is_empty());
    }
    #[test]
    fn an_active_agent_can_be_enrolled_again_and_keeps_its_identity() {
        let d = tempdir().unwrap();
        let st = StateStore::open(&d.path().join("state.db")).unwrap();
        let pools = |st: &StateStore, token: &str, id: &str, attempt: &str, key: &str| {
            st.reserve_enrollment(
                &StateStore::invite_hash(token),
                "node1",
                id,
                attempt,
                key,
                "10.6.0.0/24".parse().unwrap(),
                "fd00:6::/64".parse().unwrap(),
                "10.6.0.1".parse().unwrap(),
                "fd00:6::1".parse().unwrap(),
                120,
            )
        };
        st.invite("node1", &StateStore::invite_hash("first"), now() + 600)
            .unwrap();
        let (id, attempt) = (
            uuid::Uuid::new_v4().to_string(),
            uuid::Uuid::new_v4().to_string(),
        );
        let first = pools(&st, "first", &id, &attempt, "old-key").unwrap();
        st.activate(&id, &attempt, IpAddr::V4(first.tunnel_ipv4))
            .unwrap();

        // The reinstalled agent has a fresh identity; the invitation name may be reused.
        st.invite("node1", &StateStore::invite_hash("second"), now() + 600)
            .unwrap();
        let (new_id, new_attempt) = (
            uuid::Uuid::new_v4().to_string(),
            uuid::Uuid::new_v4().to_string(),
        );
        let again = pools(&st, "second", &new_id, &new_attempt, "new-key").unwrap();
        assert_eq!(again.id, id, "the server keeps the agent's ID");
        assert_eq!(
            (again.tunnel_ipv4, again.tunnel_ipv6),
            (first.tunnel_ipv4, first.tunnel_ipv6)
        );
        assert_eq!(again.public_key, "new-key");
        assert_eq!(again.status, AgentStatus::Active);
        assert_eq!(st.snapshot().unwrap().agents.len(), 1);
        // A retry of the same attempt gets the same answer; another attempt does not.
        assert_eq!(
            pools(&st, "second", &new_id, &new_attempt, "new-key")
                .unwrap()
                .id,
            id
        );
        assert!(pools(&st, "second", &new_id, "other", "other-key").is_err());
        assert_eq!(st.open_invites().unwrap().len(), 1);
        st.activate(&id, &new_attempt, IpAddr::V4(first.tunnel_ipv4))
            .unwrap();
        assert!(
            st.open_invites().unwrap().is_empty(),
            "the invitation is used up"
        );
        assert!(pools(&st, "second", &new_id, &new_attempt, "new-key").is_err());
    }
    #[test]
    fn cancelling_invite_removes_its_pending_agent() {
        let d = tempdir().unwrap();
        let st = StateStore::open(&d.path().join("state.db")).unwrap();
        let h = StateStore::invite_hash("token");
        st.invite("agent", &h, now() + 600).unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let attempt = uuid::Uuid::new_v4().to_string();
        st.reserve_enrollment(
            &h,
            "agent",
            &id,
            &attempt,
            "k",
            "10.6.0.0/24".parse().unwrap(),
            "fd00:6::/64".parse().unwrap(),
            "10.6.0.1".parse().unwrap(),
            "fd00:6::1".parse().unwrap(),
            120,
        )
        .unwrap();
        assert!(st.cancel_invite("agent").unwrap().agents.is_empty());
        assert!(st.invites().unwrap().is_empty());
        assert!(st
            .activate(&id, &attempt, "10.6.0.2".parse().unwrap())
            .is_err());
    }
    #[test]
    fn token_name_expiry_and_consumed_replay_are_rejected() {
        let d = tempdir().unwrap();
        let st = StateStore::open(&d.path().join("state.db")).unwrap();
        let h = StateStore::invite_hash("token");
        st.invite("agent", &h, now() + 600).unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let at = uuid::Uuid::new_v4().to_string();
        let p4 = "10.7.0.0/24".parse().unwrap();
        let p6 = "fd00:7::/64".parse().unwrap();
        assert!(st
            .reserve_enrollment(
                &h,
                "wrong-name",
                &id,
                &at,
                "k",
                p4,
                p6,
                "10.7.0.1".parse().unwrap(),
                "fd00:7::1".parse().unwrap(),
                120
            )
            .is_err());
        st.reserve_enrollment(
            &h,
            "agent",
            &id,
            &at,
            "k",
            p4,
            p6,
            "10.7.0.1".parse().unwrap(),
            "fd00:7::1".parse().unwrap(),
            120,
        )
        .unwrap();
        assert!(st
            .reserve_enrollment(
                &StateStore::invite_hash("bad-token"),
                "agent",
                &id,
                &at,
                "k",
                p4,
                p6,
                "10.7.0.1".parse().unwrap(),
                "fd00:7::1".parse().unwrap(),
                120
            )
            .is_err());
        st.activate(&id, &at, "10.7.0.2".parse().unwrap()).unwrap();
        assert!(st
            .reserve_enrollment(
                &h,
                "agent",
                &id,
                &at,
                "k",
                p4,
                p6,
                "10.7.0.1".parse().unwrap(),
                "fd00:7::1".parse().unwrap(),
                120
            )
            .is_err());
    }
    #[test]
    fn expired_stage_cannot_activate() {
        let d = tempdir().unwrap();
        let st = StateStore::open(&d.path().join("state.db")).unwrap();
        let h = StateStore::invite_hash("token");
        st.invite("agent", &h, now() + 600).unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let at = uuid::Uuid::new_v4().to_string();
        st.reserve_enrollment(
            &h,
            "agent",
            &id,
            &at,
            "k",
            "10.8.0.0/24".parse().unwrap(),
            "fd00:8::/64".parse().unwrap(),
            "10.8.0.1".parse().unwrap(),
            "fd00:8::1".parse().unwrap(),
            120,
        )
        .unwrap();
        {
            let c = st.lock().unwrap();
            c.execute(
                "UPDATE invites SET stage_deadline=?1 WHERE name='agent'",
                [now() - 1],
            )
            .unwrap();
        }
        assert!(st.activate(&id, &at, "10.8.0.2".parse().unwrap()).is_err());
    }
    #[test]
    fn state_rejects_duplicate_identity_and_forward_port_transactions() {
        let d = tempdir().unwrap();
        let st = StateStore::open(&d.path().join("state.db")).unwrap();
        let h = StateStore::invite_hash("one");
        st.invite("one", &h, now() + 600).unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let at = uuid::Uuid::new_v4().to_string();
        st.reserve_enrollment(
            &h,
            "one",
            &id,
            &at,
            "same-key",
            "10.9.0.0/24".parse().unwrap(),
            "fd00:9::/64".parse().unwrap(),
            "10.9.0.1".parse().unwrap(),
            "fd00:9::1".parse().unwrap(),
            120,
        )
        .unwrap();
        st.activate(&id, &at, "10.9.0.2".parse().unwrap()).unwrap();
        let h2 = StateStore::invite_hash("two");
        st.invite("two", &h2, now() + 600).unwrap();
        let id2 = uuid::Uuid::new_v4().to_string();
        let at2 = uuid::Uuid::new_v4().to_string();
        assert!(st
            .reserve_enrollment(
                &h2,
                "two",
                &id2,
                &at2,
                "same-key",
                "10.9.0.0/24".parse().unwrap(),
                "fd00:9::/64".parse().unwrap(),
                "10.9.0.1".parse().unwrap(),
                "fd00:9::1".parse().unwrap(),
                120
            )
            .is_err());
        let f = Forward {
            id: 1,
            agent_id: id.clone(),
            listen_ip: "203.0.113.5".parse().unwrap(),
            listen_ports: PortRange {
                start: 8080,
                end: 8081,
            },
            target_ports: PortRange { start: 80, end: 81 },
            protocol: Protocol::Tcp,
            mode: ForwardMode::Transparent,
            ingress: crate::model::Ingress::Public,
            target_family: Family::V4,
            enabled: true,
            generation: 1,
            purpose: Purpose::User,
        };
        st.mutate("forward-add", |s| {
            s.forwards.push(f.clone());
            Ok(())
        })
        .unwrap();
        let overlap = Forward {
            id: 2,
            listen_ports: PortRange {
                start: 8081,
                end: 8082,
            },
            ..f
        };
        assert!(st
            .mutate("forward-add", |s| {
                s.forwards.push(overlap);
                Ok(())
            })
            .is_err());
    }
    #[test]
    fn rotation_commit_is_idempotent() {
        let d = tempdir().unwrap();
        let st = StateStore::open(&d.path().join("state.db")).unwrap();
        let h = StateStore::invite_hash("token");
        st.invite("agent", &h, now() + 600).unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let at = uuid::Uuid::new_v4().to_string();
        st.reserve_enrollment(
            &h,
            "agent",
            &id,
            &at,
            "old",
            "10.10.0.0/24".parse().unwrap(),
            "fd00:10::/64".parse().unwrap(),
            "10.10.0.1".parse().unwrap(),
            "fd00:10::1".parse().unwrap(),
            120,
        )
        .unwrap();
        st.activate(&id, &at, "10.10.0.2".parse().unwrap()).unwrap();
        let rid = uuid::Uuid::new_v4().to_string();
        st.request_rotation(&id, &rid).unwrap();
        let first = st.commit_rotation(&id, &rid, "new").unwrap();
        let second = st.commit_rotation(&id, &rid, "new").unwrap();
        assert_eq!(first.generation, second.generation);
        assert_eq!(second.agents[0].public_key, "new");
        assert!(st.commit_rotation(&id, &rid, "different").is_err());
    }
    #[test]
    fn confirmed_generation_and_failure_survive_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("state.db");
        {
            let store = StateStore::open(&path).unwrap();
            let confirmed = store.mutate("first", |_| Ok(())).unwrap();
            store.mark_applied(&confirmed).unwrap();
            let desired = store.mutate("next", |_| Ok(())).unwrap();
            store
                .mark_failed(desired.generation, "injected apply failure")
                .unwrap();
        }
        let store = StateStore::open(&path).unwrap();
        assert_eq!(store.snapshot().unwrap().generation, 2);
        assert_eq!(store.last_applied().unwrap().unwrap().generation, 1);
        assert_eq!(
            store.apply_error().unwrap().as_deref(),
            Some("injected apply failure")
        );
        assert!(store.health().unwrap().is_empty());
    }
    #[test]
    fn connection_history_records_observed_disconnect_and_rejects_future_ack() {
        let dir = tempdir().unwrap();
        let store = StateStore::open(&dir.path().join("state.db")).unwrap();
        store
            .mutate("fixture", |state| {
                state.agents.push(AgentRecord {
                    id: "a".into(),
                    name: "a".into(),
                    public_key: "key".into(),
                    tunnel_ipv4: "10.88.0.2".parse().unwrap(),
                    tunnel_ipv6: "fd88:5249:4654::2".parse().unwrap(),
                    status: AgentStatus::Active,
                    attempt_id: "attempt".into(),
                    generation: 1,
                    applied_generation: 1,
                    last_error: None,
                    created_at: now(),
                    pending_deadline: None,
                    limits: None,
                    exit: None,
                    exit_port: None,
                });
                Ok(())
            })
            .unwrap();
        store
            .observe_health(
                &[PeerStats {
                    public_key: "key".into(),
                    last_handshake: now(),
                    ..Default::default()
                }],
                180,
            )
            .unwrap();
        assert_eq!(store.health().unwrap()[0]["online"], true);
        store.observe_health(&[], 180).unwrap();
        assert!(store.health().unwrap()[0]["last_observed_disconnect"]
            .as_i64()
            .is_some());
        assert!(store
            .update_agent_sync("a", 2, None, AgentLimits::default(), None)
            .is_err());
    }
}
