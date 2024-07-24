use crate::{update_config, Context, Result};
use chrono::{self, DateTime, Utc};
use kube::{
    api::{Api, Patch, PatchParams},
    runtime::{
        controller::Action,
        events::{Event, EventType, Recorder, Reporter},
    },
    Client, CustomResource, Resource,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::time::Duration;

pub static KACP_FINALIZER: &str = "kacp.solidite.fr";

/// Define an issuer
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct Issuer {
    /// url must be unique across all authenticators
    pub url: String,
    /// discoveryURL, if specified, overrides the URL used to fetch discovery information instead of using "{url}/.well-known/openid-configuration".
    pub discovery_u_r_l: Option<String>,
    /// PEM encoded CA certificates used to validate the connection when fetching discovery information. If not set, the system verifier will be used.
    pub certificate_authority: Option<String>,
    /// audiences is the set of acceptable audiences the JWT must be issued to. At least one of the entries must match the "aud" claim in presented JWTs. (oidc-client-id)
    pub audiences: Vec<String>,
}

/// rules applied to validate token claims to authenticate users.
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClaimValidationRule {
    /// Same as --oidc-required-claim key=value.
    pub claim: Option<String>,
    pub required_value: Option<String>,
    /// Instead of claim and requiredValue, you can use expression to validate the claim. expression is a CEL expression that evaluates to a boolean.
    pub expression: Option<String>,
    /// Message customizes the error message seen in the API server logs when the validation fails.
    pub message: Option<String>,
}

/// mapping the claim to a user
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct ClaimMappingUser {
    /// Same as --oidc-username-claim. Mutually exclusive with username.expression.
    pub claim: Option<String>,
    /// Same as --oidc-username-prefix. Mutually exclusive with username.expression. if username.claim is set, username.prefix is required. Explicitly set it to "" if no prefix is desired.
    pub prefix: Option<String>,
    /// Mutually exclusive with username.claim and username.prefix. Expression is a CEL expression that evaluates to a string.
    pub expression: Option<String>,
}

/// mapping the claim to groups
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClaimMappingGroup {
    /// Same as --oidc-groups-claim. Mutually exclusive with groups.expression.
    pub claim: Option<String>,
    /// Same as --oidc-groups-prefix. Mutually exclusive with groups.expression. if groups.claim is set, groups.prefix is required. Explicitly set it to "" if no prefix is desired.
    pub prefix: Option<String>,
    /// Mutually exclusive with groups.claim and groups.prefix. Expression is a CEL expression that evaluates to a string or a list of strings.
    pub expression: Option<String>,
}

/// mapping the claim to a uid
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClaimMappingUid {
    /// Mutually exclusive with uid.expression.
    pub claim: Option<String>,
    /// Mutually exclusive with uid.claim. expression is a CEL expression that evaluates to a string.
    pub expression: Option<String>,
}

/// extra attributes to be added to the UserInfo object. Keys must be domain-prefix path and must be unique.
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClaimMappingExtra {
    /// Identifier of the extra value
    pub key: String,
    /// valueExpression is a CEL expression that evaluates to a string or a list of strings.
    pub value_expression: String,
}

/// mapping the claim to a user
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct ClaimMapping {
    /// username represents an option for the username attribute.
    pub username: Option<ClaimMappingUser>,
    /// groups represents an option for the groups attribute
    pub groups: Option<ClaimMappingGroup>,
    /// uid represents an option for the uid attribute.
    pub uid: Option<ClaimMappingUid>,
    /// extra attributes to be added to the UserInfo object. Keys must be domain-prefix path and must be unique.
    pub extra: Option<Vec<ClaimMappingExtra>>,
}

/// validation rules applied to the final user object.
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UserValidationRule {
    /// expression is a CEL expression that evaluates to a boolean. all the expressions must evaluate to true for the user to be valid.
    pub expression: String,
    /// Message customizes the error message seen in the API server logs when the validation fails.
    pub message: String,
}

/// Describe the specification of a KubeAuthenticationConfiguration
#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[cfg_attr(test, derive(Default))]
#[kube(
    kind = "KubeAuthenticationConfiguration",
    group = "kacp.solidite.fr",
    version = "v1",
    root = "Kacp",
    doc = "Custom resource representing a AuthenticationConfiguration for kube-api-server",
    status = "KubeAuthenticationConfigurationStatus",
    shortname = "kacp"
)]
#[serde(rename_all = "camelCase")]
pub struct KubeAuthenticationConfigurationSpec {
    /// Define the OIDC issuer
    pub issuer: Issuer,
    /// rules applied to validate token claims to authenticate users.
    pub claim_validation_rules: Option<Vec<ClaimValidationRule>>,
    /// Define the how to map a claim to a user
    pub claim_mappings: Option<ClaimMapping>,
    /// validation rules applied to the final user object.
    pub user_validation_rules: Option<Vec<UserValidationRule>>,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema, Default)]
pub enum ConditionsType {
    #[default]
    Ready,
    MissingAudiance,
    InvalidClaimValidationRule,
    InvalidUsernameMapping,
    InvalidGroupMapping,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema, Default)]
pub enum ConditionsStatus {
    #[default]
    True,
    False,
}

/// ApplicationCondition contains details about an application condition, which is usually an error or warning
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationCondition {
    /// LastTransitionTime is the time the condition was last observed
    pub last_transition_time: Option<DateTime<Utc>>,
    /// Message contains human-readable message indicating details about condition
    pub message: String,
    /// Type is an application condition type
    #[serde(rename = "type")]
    pub condition_type: ConditionsType,
    /// Status ("True" or "False") describe if the condition is enbled
    pub status: ConditionsStatus,
    /// Node on which apply the status
    pub node: String,
    /// Generation for that status on that node
    pub generation: i64,
}
impl ApplicationCondition {
    #[must_use]
    pub fn new(
        message: &str,
        status: ConditionsStatus,
        condition_type: ConditionsType,
        node: &str,
        generation: i64,
    ) -> ApplicationCondition {
        ApplicationCondition {
            last_transition_time: Some(chrono::offset::Utc::now()),
            status,
            condition_type,
            message: message.into(),
            node: node.into(),
            generation,
        }
    }

    pub fn missing_audiance(message: &str, node: &str, generation: i64) -> ApplicationCondition {
        ApplicationCondition::new(
            message,
            ConditionsStatus::True,
            ConditionsType::MissingAudiance,
            node,
            generation,
        )
    }

    pub fn invalid_claim_validation_rule(
        message: &str,
        node: &str,
        generation: i64,
    ) -> ApplicationCondition {
        ApplicationCondition::new(
            message,
            ConditionsStatus::True,
            ConditionsType::InvalidClaimValidationRule,
            node,
            generation,
        )
    }

    pub fn invalid_username_mapping(
        message: &str,
        node: &str,
        generation: i64,
    ) -> ApplicationCondition {
        ApplicationCondition::new(
            message,
            ConditionsStatus::True,
            ConditionsType::InvalidUsernameMapping,
            node,
            generation,
        )
    }

    pub fn invalid_group_mapping(
        message: &str,
        node: &str,
        generation: i64,
    ) -> ApplicationCondition {
        ApplicationCondition::new(
            message,
            ConditionsStatus::True,
            ConditionsType::InvalidGroupMapping,
            node,
            generation,
        )
    }

    pub fn is_ready(message: &str, node: &str, generation: i64) -> ApplicationCondition {
        ApplicationCondition::new(
            message,
            ConditionsStatus::True,
            ConditionsType::Ready,
            node,
            generation,
        )
    }

    pub fn not_ready(message: &str, node: &str, generation: i64) -> ApplicationCondition {
        ApplicationCondition::new(
            message,
            ConditionsStatus::False,
            ConditionsType::Ready,
            node,
            generation,
        )
    }
}

/// The status object of `KubeAuthenticationConfiguration`
#[derive(Deserialize, Serialize, Clone, Default, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct KubeAuthenticationConfigurationStatus {
    pub conditions: Vec<ApplicationCondition>,
}

impl Kacp {
    pub fn condition_not_ready(&self, node: &str) -> bool {
        self.status.is_none()
            || self
                .status
                .clone()
                .unwrap()
                .conditions
                .into_iter()
                .filter(|c| c.node == node.to_string())
                .count()
                < 1
            || self
                .status
                .clone()
                .unwrap()
                .conditions
                .into_iter()
                .filter(|c| c.node == node.to_string())
                .any(|c| {
                    c.condition_type != ConditionsType::Ready
                        || c.status != ConditionsStatus::True
                        || c.generation < self.metadata.generation.unwrap_or(1)
                })
    }

    pub fn condition_not_failed(&self, node: &str) -> bool {
        self.status.is_none()
            || self
                .status
                .clone()
                .unwrap()
                .conditions
                .into_iter()
                .filter(|c| c.node == node.to_string())
                .count()
                < 1
            || self
                .status
                .clone()
                .unwrap()
                .conditions
                .into_iter()
                .filter(|c| c.node == node.to_string())
                .any(|c| {
                    c.condition_type == ConditionsType::Ready
                        && c.status == ConditionsStatus::True
                        && c.generation == self.metadata.generation.unwrap_or(1)
                })
    }

    pub async fn send_warning(
        &self,
        client: Client,
        reporter: Reporter,
        action: String,
        reason: String,
        note: Option<String>,
    ) {
        Recorder::new(client.clone(), reporter.clone(), self.object_ref(&()))
            .publish(Event {
                action,
                reason,
                note,
                type_: EventType::Warning,
                secondary: None,
            })
            .await
            .unwrap_or_default();
    }

    pub async fn send_event(
        &self,
        client: Client,
        reporter: Reporter,
        action: String,
        reason: String,
        note: Option<String>,
    ) {
        Recorder::new(client.clone(), reporter.clone(), self.object_ref(&()))
            .publish(Event {
                action,
                reason,
                note,
                type_: EventType::Normal,
                secondary: None,
            })
            .await
            .unwrap_or_default();
    }

    pub async fn save_status(
        &self,
        cfgs: Api<Kacp>,
        local_conditions: Vec<ApplicationCondition>,
        node: &str,
    ) {
        let name = self.metadata.name.clone().unwrap_or_default();
        tracing::warn!("Saving status for {name}");
        let ps = PatchParams::apply(KACP_FINALIZER).force();
        let mut conditions = local_conditions.clone();
        if let Some(status) = self.status.clone() {
            conditions.extend(
                status
                    .conditions
                    .into_iter()
                    .filter(|i| i.node != node.to_string()),
            );
        }
        let new_status = Patch::Apply(serde_json::json!({
            "apiVersion": "kacp.solidite.fr/v1",
            "kind": "KubeAuthenticationConfiguration",
            "status": KubeAuthenticationConfigurationStatus { conditions }
        }));
        cfgs.patch_status(name.as_str(), &ps, &new_status)
            .await
            .unwrap_or(self.clone());
    }

    // Reconcile (for non-finalizer related changes)
    pub async fn reconcile(&self, ctx: Arc<Context>) -> Result<Action> {
        let watched_update = || -> Result<()> {
            let context = ctx.clone();
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current()
                    .block_on(async move { update_config(context, None).await })
            })
        };
        let mut updated = false;
        if let Some(status) = self.status.clone() {
            if status
                .conditions
                .clone()
                .into_iter()
                .filter(|c| c.node == ctx.node)
                .count()
                > 0
                && status
                    .conditions
                    .clone()
                    .into_iter()
                    .filter(|c| c.node == ctx.node)
                    .any(|c| c.generation == self.metadata.generation.unwrap_or(1))
            {
                let min_delta = 15 * 60;
                let now = chrono::offset::Utc::now();
                if status
                    .conditions
                    .into_iter()
                    .filter(|i| i.node == ctx.clone().node.to_string())
                    .any(|c| {
                        (now - c.last_transition_time.unwrap_or(now)).num_seconds() > min_delta
                    })
                {
                    updated = true;
                    watched_update().unwrap_or_else(|e| tracing::warn!("{e}"));
                }
            } else if status
                .conditions
                .clone()
                .into_iter()
                .filter(|c| c.node == ctx.node)
                .count()
                < 1
                || status
                    .conditions
                    .clone()
                    .into_iter()
                    .filter(|c| c.node == ctx.node)
                    .any(|c| c.generation < self.metadata.generation.unwrap_or(1))
            {
                updated = true;
                watched_update().unwrap_or_else(|e| tracing::warn!("{e}"));
            }
        } else {
            updated = true;
            watched_update().unwrap_or_else(|e| tracing::warn!("{e}"));
        }
        if updated {
            Ok(Action::requeue(Duration::from_secs(10)))
        } else {
            Ok(Action::await_change())
        }
    }

    // Reconcile with finalize cleanup (the object was deleted)
    pub async fn cleanup(&self, ctx: Arc<Context>) -> Result<Action> {
        let watched_update = |name: &str| -> Result<()> {
            let context = ctx.clone();
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current()
                    .block_on(async move { update_config(context, Some(name)).await })
            })
        };

        watched_update(
            self.metadata
                .name
                .clone()
                .unwrap_or("no_name".into())
                .as_str(),
        )
        .unwrap_or_else(|e| tracing::warn!("{e}"));
        Ok(Action::await_change())
    }
}

impl KubeAuthenticationConfigurationSpec {
    pub fn get_conditions(
        &self,
        name: &str,
        node: &str,
        generation: i64,
    ) -> Vec<ApplicationCondition> {
        let mut conditions: Vec<ApplicationCondition> = [].to_vec();
        if self.issuer.audiences.len() < 1 {
            conditions.push(ApplicationCondition::missing_audiance(
                "Your issuer should have at least an audiance (the oidc-client-id)",
                node,
                generation,
            ));
        }
        if let Some(rules) = self.claim_validation_rules.clone() {
            for rule in rules {
                if rule.claim.is_none() && rule.expression.is_none() {
                    conditions.push(ApplicationCondition::invalid_claim_validation_rule(
                        "either 'expression' or 'claim' are requiered",
                        node,
                        generation,
                    ))
                } else if rule.claim.is_some() && rule.expression.is_some() {
                    conditions.push(ApplicationCondition::invalid_claim_validation_rule(
                        "'expression' and 'claim' are mutually exclusive",
                        node,
                        generation,
                    ))
                } else if rule.expression.is_some() && rule.message.is_none() {
                    conditions.push(ApplicationCondition::invalid_claim_validation_rule(
                        "'message' is mandatory when using 'expression'",
                        node,
                        generation,
                    ))
                } else if rule.claim.is_some() && rule.required_value.is_none() {
                    conditions.push(ApplicationCondition::invalid_claim_validation_rule(
                        "'required_value' is mandatory when using 'claim'",
                        node,
                        generation,
                    ))
                }
            }
        }
        if let Some(claim_mappings) = &self.claim_mappings {
            if let Some(usr) = &claim_mappings.username {
                if usr.claim.is_some()
                    && usr.prefix.is_some()
                    && !usr.prefix.clone().unwrap().contains(name)
                {
                    conditions.push(ApplicationCondition::invalid_username_mapping(
                        &format!("'prefix' should contain {name}"),
                        node,
                        generation,
                    ));
                } // TODO: improve user mapping validations
            }
            if let Some(grps) = &claim_mappings.groups {
                if grps.claim.is_some()
                    && grps.prefix.is_some()
                    && !grps.prefix.clone().unwrap().contains(name)
                {
                    conditions.push(ApplicationCondition::invalid_group_mapping(
                        &format!("'prefix' should contain {name}"),
                        node,
                        generation,
                    ));
                }
                // TODO: improve groups mapping validations
            }
        }
        conditions
    }
}
