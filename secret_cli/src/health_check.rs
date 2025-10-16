use crate::crypto::password::{calculate_strength, PasswordStrength};
use crate::types::{Secret, SecretStore};
use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReport {
    pub generated_at: DateTime<Utc>,
    pub overall_status: HealthStatus,
    pub checks: Vec<HealthCheck>,
    pub expired_secrets: Vec<Uuid>,
    pub weak_passwords: Vec<Uuid>,
    pub duplicate_secrets: Vec<(Uuid, Uuid)>,
    pub unused_secrets: Vec<Uuid>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub name: String,
    pub status: HealthStatus,
    pub message: String,
    pub affected_secrets: Vec<Uuid>,
    pub recommendation: Option<String>,
}

pub struct HealthChecker;

impl HealthChecker {
    pub fn new() -> Self {
        Self
    }

    /// Perform a comprehensive health check
    pub fn check_health(&self, store: &SecretStore) -> Result<HealthReport> {
        let mut checks = Vec::new();
        let mut recommendations = Vec::new();

        // Check for expired secrets
        let expired_check = self.check_expired_secrets(store);
        let expired_secrets: Vec<Uuid> = expired_check.affected_secrets.clone();
        checks.push(expired_check);

        // Check for weak passwords
        let weak_check = self.check_weak_passwords(store);
        let weak_passwords: Vec<Uuid> = weak_check.affected_secrets.clone();
        checks.push(weak_check);

        // Check for duplicate secrets
        let duplicate_check = self.check_duplicate_secrets(store);
        let duplicate_secrets = self.find_duplicates(store);
        checks.push(duplicate_check);

        // Check for unused/old secrets
        let unused_check = self.check_unused_secrets(store);
        let unused_secrets: Vec<Uuid> = unused_check.affected_secrets.clone();
        checks.push(unused_check);

        // Check secret age distribution
        let age_check = self.check_secret_age_distribution(store);
        checks.push(age_check);

        // Check for secrets without categories
        let category_check = self.check_uncategorized_secrets(store);
        checks.push(category_check);

        // Determine overall status
        let overall_status = self.determine_overall_status(&checks);

        // Generate recommendations
        if !expired_secrets.is_empty() {
            recommendations.push(format!(
                "Update or remove {} expired secret(s)",
                expired_secrets.len()
            ));
        }

        if !weak_passwords.is_empty() {
            recommendations.push(format!(
                "Strengthen {} weak password(s)",
                weak_passwords.len()
            ));
        }

        if !duplicate_secrets.is_empty() {
            recommendations.push(format!(
                "Review {} duplicate secret(s)",
                duplicate_secrets.len()
            ));
        }

        if !unused_secrets.is_empty() {
            recommendations.push(format!(
                "Consider archiving {} unused secret(s) (not accessed in 90+ days)",
                unused_secrets.len()
            ));
        }

        Ok(HealthReport {
            generated_at: Utc::now(),
            overall_status,
            checks,
            expired_secrets,
            weak_passwords,
            duplicate_secrets,
            unused_secrets,
            recommendations,
        })
    }

    /// Check for expired secrets
    pub fn check_expired_secrets(&self, store: &SecretStore) -> HealthCheck {
        let expired_secrets: Vec<Uuid> = store
            .secrets
            .values()
            .filter(|secret| secret.is_expired())
            .map(|secret| secret.id)
            .collect();

        let status = if expired_secrets.is_empty() {
            HealthStatus::Healthy
        } else if expired_secrets.len() <= 3 {
            HealthStatus::Warning
        } else {
            HealthStatus::Critical
        };

        let message = if expired_secrets.is_empty() {
            "No expired secrets found".to_string()
        } else {
            format!("Found {} expired secret(s)", expired_secrets.len())
        };

        HealthCheck {
            name: "Expired Secrets".to_string(),
            status,
            message,
            affected_secrets: expired_secrets.clone(),
            recommendation: if !expired_secrets.is_empty() {
                Some("Update or remove expired secrets to maintain security".to_string())
            } else {
                None
            },
        }
    }

    /// Check for weak passwords
    pub fn check_weak_passwords(&self, store: &SecretStore) -> HealthCheck {
        let weak_secrets: Vec<Uuid> = store
            .secrets
            .values()
            .filter(|secret| {
                // Only check secrets that look like passwords
                if self.looks_like_password(secret) {
                    matches!(
                        calculate_strength(&secret.value),
                        PasswordStrength::Weak | PasswordStrength::Fair
                    )
                } else {
                    false
                }
            })
            .map(|secret| secret.id)
            .collect();

        let status = if weak_secrets.is_empty() {
            HealthStatus::Healthy
        } else if weak_secrets.len() <= 2 {
            HealthStatus::Warning
        } else {
            HealthStatus::Critical
        };

        let message = if weak_secrets.is_empty() {
            "All passwords have adequate strength".to_string()
        } else {
            format!("Found {} weak password(s)", weak_secrets.len())
        };

        HealthCheck {
            name: "Password Strength".to_string(),
            status,
            message,
            affected_secrets: weak_secrets.clone(),
            recommendation: if !weak_secrets.is_empty() {
                Some("Use stronger passwords with a mix of characters, numbers, and symbols".to_string())
            } else {
                None
            },
        }
    }

    /// Check for duplicate secrets
    pub fn check_duplicate_secrets(&self, store: &SecretStore) -> HealthCheck {
        let duplicates = self.find_duplicates(store);

        let status = if duplicates.is_empty() {
            HealthStatus::Healthy
        } else if duplicates.len() <= 2 {
            HealthStatus::Warning
        } else {
            HealthStatus::Critical
        };

        let message = if duplicates.is_empty() {
            "No duplicate secrets found".to_string()
        } else {
            format!("Found {} duplicate secret pair(s)", duplicates.len())
        };

        HealthCheck {
            name: "Duplicate Secrets".to_string(),
            status,
            message,
            affected_secrets: duplicates.iter().flat_map(|(a, b)| vec![*a, *b]).collect(),
            recommendation: if !duplicates.is_empty() {
                Some("Review and consolidate duplicate secrets".to_string())
            } else {
                None
            },
        }
    }

    /// Check for unused secrets (not accessed in 90+ days)
    pub fn check_unused_secrets(&self, store: &SecretStore) -> HealthCheck {
        let cutoff_date = Utc::now() - Duration::days(90);
        
        let unused_secrets: Vec<Uuid> = store
            .secrets
            .values()
            .filter(|secret| {
                secret.last_accessed
                    .map(|accessed| accessed < cutoff_date)
                    .unwrap_or(true) // Never accessed
            })
            .map(|secret| secret.id)
            .collect();

        let status = if unused_secrets.is_empty() {
            HealthStatus::Healthy
        } else if unused_secrets.len() <= 5 {
            HealthStatus::Warning
        } else {
            HealthStatus::Critical
        };

        let message = if unused_secrets.is_empty() {
            "All secrets have been accessed recently".to_string()
        } else {
            format!("Found {} unused secret(s) (90+ days)", unused_secrets.len())
        };

        HealthCheck {
            name: "Secret Usage".to_string(),
            status,
            message,
            affected_secrets: unused_secrets.clone(),
            recommendation: if !unused_secrets.is_empty() {
                Some("Consider archiving or removing secrets that haven't been used recently".to_string())
            } else {
                None
            },
        }
    }

    /// Check secret age distribution
    pub fn check_secret_age_distribution(&self, store: &SecretStore) -> HealthCheck {
        let now = Utc::now();
        let mut age_buckets = HashMap::new();

        for secret in store.secrets.values() {
            let age_days = (now - secret.created_at).num_days();
            let bucket = match age_days {
                0..=30 => "0-30 days",
                31..=90 => "31-90 days",
                91..=365 => "91-365 days",
                _ => "1+ years",
            };
            *age_buckets.entry(bucket).or_insert(0) += 1;
        }

        let old_secrets_count = age_buckets.get("1+ years").unwrap_or(&0);
        let total_secrets = store.secrets.len();

        let status = if total_secrets == 0 {
            HealthStatus::Healthy
        } else {
            let old_percentage = (*old_secrets_count as f64 / total_secrets as f64) * 100.0;
            if old_percentage > 50.0 {
                HealthStatus::Warning
            } else {
                HealthStatus::Healthy
            }
        };

        let message = format!(
            "Secret age distribution: {} total secrets, {} are 1+ years old",
            total_secrets, old_secrets_count
        );

        HealthCheck {
            name: "Secret Age Distribution".to_string(),
            status,
            message,
            affected_secrets: Vec::new(),
            recommendation: if *old_secrets_count > 0 {
                Some("Consider reviewing and rotating old secrets".to_string())
            } else {
                None
            },
        }
    }

    /// Check for secrets without categories
    pub fn check_uncategorized_secrets(&self, store: &SecretStore) -> HealthCheck {
        let uncategorized: Vec<Uuid> = store
            .secrets
            .values()
            .filter(|secret| secret.category.is_none())
            .map(|secret| secret.id)
            .collect();

        let status = if uncategorized.is_empty() {
            HealthStatus::Healthy
        } else if uncategorized.len() <= 3 {
            HealthStatus::Warning
        } else {
            HealthStatus::Critical
        };

        let message = if uncategorized.is_empty() {
            "All secrets are properly categorized".to_string()
        } else {
            format!("Found {} uncategorized secret(s)", uncategorized.len())
        };

        HealthCheck {
            name: "Secret Organization".to_string(),
            status,
            message,
            affected_secrets: uncategorized.clone(),
            recommendation: if !uncategorized.is_empty() {
                Some("Add categories to secrets for better organization".to_string())
            } else {
                None
            },
        }
    }

    // Helper methods

    fn find_duplicates(&self, store: &SecretStore) -> Vec<(Uuid, Uuid)> {
        let mut duplicates = Vec::new();
        let secrets: Vec<&Secret> = store.secrets.values().collect();

        for i in 0..secrets.len() {
            for j in i + 1..secrets.len() {
                if secrets[i].value == secrets[j].value && !secrets[i].value.is_empty() {
                    duplicates.push((secrets[i].id, secrets[j].id));
                }
            }
        }

        duplicates
    }

    fn looks_like_password(&self, secret: &Secret) -> bool {
        // Simple heuristics to determine if a secret looks like a password
        let name_lower = secret.name.to_lowercase();
        let category_lower = secret.category.as_deref().unwrap_or("").to_lowercase();

        name_lower.contains("password") ||
        name_lower.contains("passwd") ||
        name_lower.contains("pwd") ||
        category_lower.contains("password") ||
        category_lower.contains("auth") ||
        // Length and complexity checks
        (secret.value.len() >= 8 && secret.value.len() <= 128 &&
         secret.value.chars().any(|c| c.is_alphabetic()) &&
         !secret.value.contains("://") && // Not likely to be a URL
         !secret.value.starts_with("-----")) // Not likely to be a key/cert
    }

    fn determine_overall_status(&self, checks: &[HealthCheck]) -> HealthStatus {
        if checks.iter().any(|check| matches!(check.status, HealthStatus::Critical)) {
            HealthStatus::Critical
        } else if checks.iter().any(|check| matches!(check.status, HealthStatus::Warning)) {
            HealthStatus::Warning
        } else {
            HealthStatus::Healthy
        }
    }
}

impl std::fmt::Display for HealthReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Health Report - {}", self.generated_at.format("%Y-%m-%d %H:%M UTC"))?;
        writeln!(f, "Overall Status: {:?}", self.overall_status)?;
        writeln!(f)?;

        for check in &self.checks {
            writeln!(f, "❯ {} [{:?}]", check.name, check.status)?;
            writeln!(f, "  {}", check.message)?;
            if let Some(recommendation) = &check.recommendation {
                writeln!(f, "  💡 {}", recommendation)?;
            }
            writeln!(f)?;
        }

        if !self.recommendations.is_empty() {
            writeln!(f, "🔧 Recommendations:")?;
            for rec in &self.recommendations {
                writeln!(f, "  • {}", rec)?;
            }
        }

        Ok(())
    }
}