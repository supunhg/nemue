// Report collaboration with shared reports, comments, annotations, versioning, and access control
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollaborationManager {
    pub shared_reports: Vec<SharedReport>,
    pub access_policies: Vec<AccessPolicy>,
    pub audit_log: Vec<CollabAuditEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedReport {
    pub report_id: String,
    pub title: String,
    pub owner: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub versions: Vec<ReportVersion>,
    pub comments: Vec<Comment>,
    pub annotations: Vec<Annotation>,
    pub shares: Vec<ShareEntry>,
    pub tags: Vec<String>,
    pub status: ReportStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportVersion {
    pub version_id: String,
    pub version_number: u32,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub change_summary: String,
    pub content_hash: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Comment {
    pub comment_id: String,
    pub author: String,
    pub content: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
    pub parent_comment_id: Option<String>,
    pub finding_id: Option<String>,
    pub resolved: bool,
    pub reactions: Vec<Reaction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reaction {
    pub user: String,
    pub emoji: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotation {
    pub annotation_id: String,
    pub author: String,
    pub annotation_type: AnnotationKind,
    pub target_id: String,
    pub content: String,
    pub created_at: DateTime<Utc>,
    pub color: Option<String>,
    pub page_number: Option<u32>,
    pub coordinates: Option<AnnotationCoordinates>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AnnotationKind {
    Highlight,
    Note,
    Bookmark,
    Flag,
    Correction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnotationCoordinates {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareEntry {
    pub shared_with: String,
    pub permission: Permission,
    pub shared_at: DateTime<Utc>,
    pub shared_by: String,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Permission {
    View,
    Comment,
    Edit,
    Admin,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReportStatus {
    Draft,
    UnderReview,
    Approved,
    Published,
    Archived,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPolicy {
    pub policy_id: String,
    pub name: String,
    pub description: String,
    pub rules: Vec<AccessRule>,
    pub created_at: DateTime<Utc>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRule {
    pub subject: String,
    pub resource_pattern: String,
    pub permission: Permission,
    pub conditions: Vec<AccessCondition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessCondition {
    pub field: String,
    pub operator: ConditionOperator,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConditionOperator {
    Equals,
    NotEquals,
    Contains,
    StartsWith,
    EndsWith,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollabAuditEntry {
    pub timestamp: DateTime<Utc>,
    pub user: String,
    pub action: CollabAction,
    pub resource_id: String,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CollabAction {
    ViewReport,
    AddComment,
    EditComment,
    DeleteComment,
    AddAnnotation,
    ShareReport,
    RevokeAccess,
    ChangeStatus,
    AddVersion,
    ResolveComment,
}

impl Default for CollaborationManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CollaborationManager {
    pub fn new() -> Self {
        Self {
            shared_reports: Vec::new(),
            access_policies: Vec::new(),
            audit_log: Vec::new(),
        }
    }

    pub fn create_shared_report(
        &mut self,
        report_id: &str,
        title: &str,
        owner: &str,
    ) -> &SharedReport {
        let report = SharedReport {
            report_id: report_id.to_string(),
            title: title.to_string(),
            owner: owner.to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            versions: Vec::new(),
            comments: Vec::new(),
            annotations: Vec::new(),
            shares: Vec::new(),
            tags: Vec::new(),
            status: ReportStatus::Draft,
        };
        self.shared_reports.push(report);
        self.shared_reports.last().unwrap()
    }

    pub fn get_report(&self, report_id: &str) -> Option<&SharedReport> {
        self.shared_reports
            .iter()
            .find(|r| r.report_id == report_id)
    }

    pub fn get_report_mut(&mut self, report_id: &str) -> Option<&mut SharedReport> {
        self.shared_reports
            .iter_mut()
            .find(|r| r.report_id == report_id)
    }

    pub fn delete_report(&mut self, report_id: &str) -> bool {
        let len = self.shared_reports.len();
        self.shared_reports.retain(|r| r.report_id != report_id);
        self.shared_reports.len() < len
    }

    pub fn check_permission(&self, user: &str, report_id: &str, required: Permission) -> bool {
        if let Some(report) = self.get_report(report_id) {
            if report.owner == user {
                return true;
            }
            if let Some(share) = report.shares.iter().find(|s| s.shared_with == user) {
                if let Some(exp) = share.expires_at {
                    if Utc::now() > exp {
                        return false;
                    }
                }
                return share.permission >= required;
            }
        }
        false
    }

    pub fn log_action(
        &mut self,
        user: &str,
        action: CollabAction,
        resource_id: &str,
        details: &str,
    ) {
        self.audit_log.push(CollabAuditEntry {
            timestamp: Utc::now(),
            user: user.to_string(),
            action,
            resource_id: resource_id.to_string(),
            details: details.to_string(),
        });
    }

    pub fn get_audit_log(&self, resource_id: Option<&str>) -> Vec<&CollabAuditEntry> {
        match resource_id {
            Some(id) => self
                .audit_log
                .iter()
                .filter(|e| e.resource_id == id)
                .collect(),
            None => self.audit_log.iter().collect(),
        }
    }

    pub fn add_access_policy(&mut self, policy: AccessPolicy) {
        self.access_policies.push(policy);
    }

    pub fn get_access_policy(&self, policy_id: &str) -> Option<&AccessPolicy> {
        self.access_policies
            .iter()
            .find(|p| p.policy_id == policy_id)
    }
}

impl SharedReport {
    pub fn add_version(
        &mut self,
        version_id: &str,
        created_by: &str,
        change_summary: &str,
        content_hash: &str,
        size_bytes: u64,
    ) {
        let version_number = self.versions.len() as u32 + 1;
        self.versions.push(ReportVersion {
            version_id: version_id.to_string(),
            version_number,
            created_at: Utc::now(),
            created_by: created_by.to_string(),
            change_summary: change_summary.to_string(),
            content_hash: content_hash.to_string(),
            size_bytes,
        });
        self.updated_at = Utc::now();
    }

    pub fn latest_version(&self) -> Option<&ReportVersion> {
        self.versions.last()
    }

    pub fn get_version(&self, version_number: u32) -> Option<&ReportVersion> {
        self.versions
            .iter()
            .find(|v| v.version_number == version_number)
    }

    pub fn add_comment(
        &mut self,
        comment_id: &str,
        author: &str,
        content: &str,
        finding_id: Option<&str>,
        parent_comment_id: Option<&str>,
    ) {
        self.comments.push(Comment {
            comment_id: comment_id.to_string(),
            author: author.to_string(),
            content: content.to_string(),
            created_at: Utc::now(),
            updated_at: None,
            parent_comment_id: parent_comment_id.map(|s| s.to_string()),
            finding_id: finding_id.map(|s| s.to_string()),
            resolved: false,
            reactions: Vec::new(),
        });
        self.updated_at = Utc::now();
    }

    pub fn get_comments_for_finding(&self, finding_id: &str) -> Vec<&Comment> {
        self.comments
            .iter()
            .filter(|c| c.finding_id.as_deref() == Some(finding_id))
            .collect()
    }

    pub fn get_thread_comments(&self, parent_id: &str) -> Vec<&Comment> {
        self.comments
            .iter()
            .filter(|c| c.parent_comment_id.as_deref() == Some(parent_id))
            .collect()
    }

    pub fn resolve_comment(&mut self, comment_id: &str) -> bool {
        if let Some(comment) = self
            .comments
            .iter_mut()
            .find(|c| c.comment_id == comment_id)
        {
            comment.resolved = true;
            comment.updated_at = Some(Utc::now());
            self.updated_at = Utc::now();
            true
        } else {
            false
        }
    }

    pub fn unresolved_comment_count(&self) -> usize {
        self.comments.iter().filter(|c| !c.resolved).count()
    }

    pub fn add_annotation(&mut self, annotation: Annotation) {
        self.annotations.push(annotation);
        self.updated_at = Utc::now();
    }

    pub fn get_annotations_by_type(&self, kind: &AnnotationKind) -> Vec<&Annotation> {
        self.annotations
            .iter()
            .filter(|a| &a.annotation_type == kind)
            .collect()
    }

    pub fn remove_annotation(&mut self, annotation_id: &str) -> bool {
        let len = self.annotations.len();
        self.annotations
            .retain(|a| a.annotation_id != annotation_id);
        self.annotations.len() < len
    }

    pub fn share_with(
        &mut self,
        shared_with: &str,
        permission: Permission,
        shared_by: &str,
        expires_at: Option<DateTime<Utc>>,
    ) {
        self.shares.retain(|s| s.shared_with != shared_with);
        self.shares.push(ShareEntry {
            shared_with: shared_with.to_string(),
            permission,
            shared_at: Utc::now(),
            shared_by: shared_by.to_string(),
            expires_at,
        });
        self.updated_at = Utc::now();
    }

    pub fn revoke_access(&mut self, user: &str) -> bool {
        let len = self.shares.len();
        self.shares.retain(|s| s.shared_with != user);
        self.shares.len() < len
    }

    pub fn change_status(&mut self, status: ReportStatus) {
        self.status = status;
        self.updated_at = Utc::now();
    }

    pub fn add_tag(&mut self, tag: &str) {
        if !self.tags.contains(&tag.to_string()) {
            self.tags.push(tag.to_string());
        }
    }

    pub fn remove_tag(&mut self, tag: &str) {
        self.tags.retain(|t| t != tag);
    }

    pub fn get_users_with_access(&self) -> Vec<(&str, Permission)> {
        let mut users: Vec<(&str, Permission)> = vec![(self.owner.as_str(), Permission::Admin)];
        for share in &self.shares {
            users.push((share.shared_with.as_str(), share.permission));
        }
        users
    }
}

impl PartialOrd for Permission {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Permission {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let self_val = match self {
            Permission::View => 0,
            Permission::Comment => 1,
            Permission::Edit => 2,
            Permission::Admin => 3,
        };
        let other_val = match other {
            Permission::View => 0,
            Permission::Comment => 1,
            Permission::Edit => 2,
            Permission::Admin => 3,
        };
        self_val.cmp(&other_val)
    }
}

impl PartialEq for Permission {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Permission::View, Permission::View)
                | (Permission::Comment, Permission::Comment)
                | (Permission::Edit, Permission::Edit)
                | (Permission::Admin, Permission::Admin)
        )
    }
}

impl Eq for Permission {}

impl AccessPolicy {
    pub fn new(policy_id: &str, name: &str, description: &str) -> Self {
        Self {
            policy_id: policy_id.to_string(),
            name: name.to_string(),
            description: description.to_string(),
            rules: Vec::new(),
            created_at: Utc::now(),
            enabled: true,
        }
    }

    pub fn add_rule(&mut self, rule: AccessRule) {
        self.rules.push(rule);
    }

    pub fn evaluate(&self, subject: &str, resource: &str, required_permission: Permission) -> bool {
        if !self.enabled {
            return false;
        }
        self.rules.iter().any(|rule| {
            (rule.subject == subject || rule.subject == "*")
                && Self::matches_pattern(&rule.resource_pattern, resource)
                && rule.permission >= required_permission
        })
    }

    fn matches_pattern(pattern: &str, value: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        if let Some(prefix) = pattern.strip_suffix('*') {
            return value.starts_with(prefix);
        }
        pattern == value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_collab() -> (CollaborationManager, String) {
        let mut mgr = CollaborationManager::new();
        mgr.create_shared_report("r1", "Q1 Security Report", "alice");
        (mgr, "r1".to_string())
    }

    #[test]
    fn test_create_shared_report() {
        let (mgr, _) = setup_collab();
        let report = mgr.get_report("r1").unwrap();
        assert_eq!(report.title, "Q1 Security Report");
        assert_eq!(report.owner, "alice");
        assert_eq!(report.status, ReportStatus::Draft);
    }

    #[test]
    fn test_report_not_found() {
        let mgr = CollaborationManager::new();
        assert!(mgr.get_report("nonexistent").is_none());
    }

    #[test]
    fn test_delete_report() {
        let (mut mgr, _) = setup_collab();
        assert!(mgr.delete_report("r1"));
        assert!(mgr.get_report("r1").is_none());
        assert!(!mgr.delete_report("r1"));
    }

    #[test]
    fn test_add_version() {
        let (mut mgr, _) = setup_collab();
        let report = mgr.get_report_mut("r1").unwrap();
        report.add_version("v1", "alice", "Initial version", "abc123", 1024);
        report.add_version("v2", "alice", "Added findings", "def456", 2048);

        assert_eq!(report.versions.len(), 2);
        assert_eq!(report.latest_version().unwrap().version_number, 2);
        assert_eq!(
            report.get_version(1).unwrap().change_summary,
            "Initial version"
        );
    }

    #[test]
    fn test_comments() {
        let (mut mgr, _) = setup_collab();
        let report = mgr.get_report_mut("r1").unwrap();

        report.add_comment("c1", "bob", "Looks good", None, None);
        report.add_comment("c2", "charlie", "I disagree", Some("finding-1"), Some("c1"));

        assert_eq!(report.comments.len(), 2);
        assert_eq!(report.get_comments_for_finding("finding-1").len(), 1);
        assert_eq!(report.get_thread_comments("c1").len(), 1);
    }

    #[test]
    fn test_resolve_comment() {
        let (mut mgr, _) = setup_collab();
        let report = mgr.get_report_mut("r1").unwrap();
        report.add_comment("c1", "bob", "Check this", None, None);

        assert_eq!(report.unresolved_comment_count(), 1);
        assert!(report.resolve_comment("c1"));
        assert_eq!(report.unresolved_comment_count(), 0);
        assert!(!report.resolve_comment("nonexistent"));
    }

    #[test]
    fn test_annotations() {
        let (mut mgr, _) = setup_collab();
        let report = mgr.get_report_mut("r1").unwrap();

        report.add_annotation(Annotation {
            annotation_id: "a1".to_string(),
            author: "bob".to_string(),
            annotation_type: AnnotationKind::Highlight,
            target_id: "finding-1".to_string(),
            content: "Important finding".to_string(),
            created_at: Utc::now(),
            color: Some("yellow".to_string()),
            page_number: Some(3),
            coordinates: None,
        });
        report.add_annotation(Annotation {
            annotation_id: "a2".to_string(),
            author: "charlie".to_string(),
            annotation_type: AnnotationKind::Flag,
            target_id: "finding-2".to_string(),
            content: "Needs review".to_string(),
            created_at: Utc::now(),
            color: Some("red".to_string()),
            page_number: None,
            coordinates: None,
        });

        assert_eq!(report.annotations.len(), 2);
        assert_eq!(
            report
                .get_annotations_by_type(&AnnotationKind::Highlight)
                .len(),
            1
        );
        assert_eq!(
            report.get_annotations_by_type(&AnnotationKind::Flag).len(),
            1
        );

        assert!(report.remove_annotation("a1"));
        assert_eq!(report.annotations.len(), 1);
    }

    #[test]
    fn test_sharing() {
        let (mut mgr, _) = setup_collab();
        let report = mgr.get_report_mut("r1").unwrap();

        report.share_with("bob", Permission::View, "alice", None);
        report.share_with(
            "charlie",
            Permission::Edit,
            "alice",
            Some(Utc::now() + chrono::Duration::days(30)),
        );

        assert_eq!(report.shares.len(), 2);
        assert_eq!(report.get_users_with_access().len(), 3); // owner + 2 shares
    }

    #[test]
    fn test_revoke_access() {
        let (mut mgr, _) = setup_collab();
        let report = mgr.get_report_mut("r1").unwrap();
        report.share_with("bob", Permission::View, "alice", None);

        assert!(report.revoke_access("bob"));
        assert_eq!(report.shares.len(), 0);
        assert!(!report.revoke_access("bob"));
    }

    #[test]
    fn test_check_permission() {
        let (mut mgr, _) = setup_collab();
        {
            let report = mgr.get_report_mut("r1").unwrap();
            report.share_with("bob", Permission::Comment, "alice", None);
            report.share_with("charlie", Permission::View, "alice", None);
        }

        assert!(mgr.check_permission("alice", "r1", Permission::Admin));
        assert!(mgr.check_permission("bob", "r1", Permission::Comment));
        assert!(!mgr.check_permission("bob", "r1", Permission::Edit));
        assert!(mgr.check_permission("charlie", "r1", Permission::View));
        assert!(!mgr.check_permission("dave", "r1", Permission::View));
    }

    #[test]
    fn test_expired_share() {
        let (mut mgr, _) = setup_collab();
        {
            let report = mgr.get_report_mut("r1").unwrap();
            report.share_with(
                "bob",
                Permission::View,
                "alice",
                Some(Utc::now() - chrono::Duration::hours(1)),
            );
        }

        assert!(!mgr.check_permission("bob", "r1", Permission::View));
    }

    #[test]
    fn test_report_status() {
        let (mut mgr, _) = setup_collab();
        let report = mgr.get_report_mut("r1").unwrap();

        assert_eq!(report.status, ReportStatus::Draft);
        report.change_status(ReportStatus::UnderReview);
        assert_eq!(report.status, ReportStatus::UnderReview);
        report.change_status(ReportStatus::Approved);
        assert_eq!(report.status, ReportStatus::Approved);
    }

    #[test]
    fn test_tags() {
        let (mut mgr, _) = setup_collab();
        let report = mgr.get_report_mut("r1").unwrap();

        report.add_tag("security");
        report.add_tag("q1");
        report.add_tag("security"); // duplicate
        assert_eq!(report.tags.len(), 2);

        report.remove_tag("q1");
        assert_eq!(report.tags.len(), 1);
    }

    #[test]
    fn test_audit_log() {
        let (mut mgr, _) = setup_collab();
        mgr.log_action("alice", CollabAction::ShareReport, "r1", "Shared with bob");
        mgr.log_action("bob", CollabAction::ViewReport, "r1", "Viewed report");

        assert_eq!(mgr.audit_log.len(), 2);
        let r1_log = mgr.get_audit_log(Some("r1"));
        assert_eq!(r1_log.len(), 2);

        let all_log = mgr.get_audit_log(None);
        assert_eq!(all_log.len(), 2);
    }

    #[test]
    fn test_access_policy() {
        let mut policy = AccessPolicy::new("p1", "Team Access", "Allow team access to reports");
        policy.add_rule(AccessRule {
            subject: "bob".to_string(),
            resource_pattern: "r*".to_string(),
            permission: Permission::View,
            conditions: vec![],
        });
        policy.add_rule(AccessRule {
            subject: "*".to_string(),
            resource_pattern: "public-*".to_string(),
            permission: Permission::View,
            conditions: vec![],
        });

        assert!(policy.evaluate("bob", "r1", Permission::View));
        assert!(!policy.evaluate("bob", "r1", Permission::Edit));
        assert!(policy.evaluate("anyone", "public-report", Permission::View));
        assert!(!policy.evaluate("bob", "other-report", Permission::View));
    }

    #[test]
    fn test_access_policy_disabled() {
        let mut policy = AccessPolicy::new("p1", "Test", "Test");
        policy.add_rule(AccessRule {
            subject: "*".to_string(),
            resource_pattern: "*".to_string(),
            permission: Permission::Admin,
            conditions: vec![],
        });

        assert!(policy.evaluate("anyone", "anything", Permission::View));
        policy.enabled = false;
        assert!(!policy.evaluate("anyone", "anything", Permission::View));
    }

    #[test]
    fn test_permission_ordering() {
        assert!(Permission::View < Permission::Comment);
        assert!(Permission::Comment < Permission::Edit);
        assert!(Permission::Edit < Permission::Admin);
    }

    #[test]
    fn test_annotation_kinds() {
        assert_ne!(AnnotationKind::Highlight, AnnotationKind::Note);
        assert_ne!(AnnotationKind::Bookmark, AnnotationKind::Flag);
    }

    #[test]
    fn test_collab_action_types() {
        assert_ne!(CollabAction::ViewReport, CollabAction::AddComment);
        assert_ne!(CollabAction::ShareReport, CollabAction::RevokeAccess);
    }

    #[test]
    fn test_report_version_ordering() {
        let (mut mgr, _) = setup_collab();
        let report = mgr.get_report_mut("r1").unwrap();

        report.add_version("v1", "alice", "First", "hash1", 100);
        report.add_version("v2", "alice", "Second", "hash2", 200);
        report.add_version("v3", "alice", "Third", "hash3", 300);

        assert_eq!(report.latest_version().unwrap().version_number, 3);
        assert_eq!(report.get_version(2).unwrap().size_bytes, 200);
    }

    #[test]
    fn test_condition_operators() {
        assert_ne!(ConditionOperator::Equals, ConditionOperator::Contains);
        assert_ne!(ConditionOperator::StartsWith, ConditionOperator::EndsWith);
    }
}
