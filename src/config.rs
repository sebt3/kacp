use crate::{
    ClaimMapping, ClaimMappingExtra, ClaimMappingGroup, ClaimMappingUid, ClaimMappingUser,
    Error::{StdIo, YamlError},
    KubeAuthenticationConfigurationSpec, Result, UserValidationRule,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Default mapping the claim to a user
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct DefaultClaimMapping {
    /// username represents an option for the username attribute.
    pub username: Option<ClaimMappingUser>,
    /// groups represents an option for the groups attribute
    pub groups: Option<ClaimMappingGroup>,
    /// uid represents an option for the uid attribute.
    pub uid: Option<ClaimMappingUid>,
    /// extra attributes to be added to the UserInfo object. Keys must be domain-prefix path and must be unique.
    pub extra: Option<Vec<ClaimMappingExtra>>,
}

/// Configuration
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct Configuration {
    /// Default mapping the claim to a user
    pub default_claim_mapping: Option<DefaultClaimMapping>,
    /// extra userValidationRules that will be added to every kacp
    pub extra_user_validation_rules: Option<Vec<UserValidationRule>>,
}

impl Configuration {
    pub fn new() -> Configuration {
        Configuration {
            default_claim_mapping: None,
            extra_user_validation_rules: None,
        }
    }
    pub fn load_from(file: PathBuf) -> Result<Configuration> {
        let file = std::fs::File::open(file).map_err(|e| StdIo(e))?;
        Ok(serde_yaml::from_reader(file).map_err(|e| YamlError(e))?)
    }
    fn get_claim_mapping(&self, prefix: &str) -> ClaimMapping {
        let mut ret = ClaimMapping {
            username: if self
                .default_claim_mapping
                .clone()
                .is_some_and(|dcm| dcm.username.is_some())
            {
                Some(
                    self.default_claim_mapping
                        .clone()
                        .unwrap()
                        .username
                        .unwrap(),
                )
            } else {
                Some(ClaimMappingUser {
                    claim: Some("email".into()),
                    prefix: Some(prefix.into()),
                    expression: None,
                })
            },
            groups: if self
                .default_claim_mapping
                .clone()
                .is_some_and(|dcm| dcm.groups.is_some())
            {
                Some(self.default_claim_mapping.clone().unwrap().groups.unwrap())
            } else {
                Some(ClaimMappingGroup {
                    claim: Some("groups".into()),
                    prefix: Some(prefix.into()),
                    expression: None,
                })
            },
            uid: if self
                .default_claim_mapping
                .clone()
                .is_some_and(|dcm| dcm.uid.is_some())
            {
                Some(self.default_claim_mapping.clone().unwrap().uid.unwrap())
            } else {
                None
            },
            extra: if self
                .default_claim_mapping
                .clone()
                .is_some_and(|dcm| dcm.extra.is_some())
            {
                Some(self.default_claim_mapping.clone().unwrap().extra.unwrap())
            } else {
                None
            },
        };
        if let Some(mut usr) = ret.username {
            if usr.claim.is_some() && usr.prefix.is_none() {
                usr.prefix = Some(prefix.into());
            }
            ret.username = Some(usr)
        }
        if let Some(mut grp) = ret.groups {
            if grp.claim.is_some() && grp.prefix.is_none() {
                grp.prefix = Some(prefix.into());
            }
            ret.groups = Some(grp)
        }
        ret
    }

    pub fn apply_to(
        &self,
        cfg: &KubeAuthenticationConfigurationSpec,
        name: &str,
    ) -> Result<KubeAuthenticationConfigurationSpec> {
        let mut ret = cfg.clone();
        let dcm = self.get_claim_mapping(&format!("tenant:{name}:"));

        if let Some(mut cm) = ret.claim_mappings {
            if cm.username.is_none() {
                cm.username = dcm.username;
            }
            if cm.groups.is_none() {
                cm.groups = dcm.groups;
            }
            if cm.uid.is_none() {
                cm.uid = dcm.uid;
            }
            if cm.extra.is_none() {
                cm.extra = dcm.extra;
            }
            if let Some(mut usr) = cm.username {
                if usr.claim.is_some() && usr.prefix.is_none() {
                    usr.prefix = Some(name.into());
                }
                cm.username = Some(usr);
            }
            if let Some(mut grp) = cm.groups {
                if grp.claim.is_some() && grp.prefix.is_none() {
                    grp.prefix = Some(name.into());
                }
                cm.groups = Some(grp);
            }
            ret.claim_mappings = Some(cm);
        } else {
            ret.claim_mappings = Some(dcm);
        }
        if let Some(mut extra) = self.extra_user_validation_rules.clone() {
            if let Some(mut uvr) = ret.user_validation_rules {
                uvr.append(&mut extra);
                ret.user_validation_rules = Some(uvr);
            } else {
                ret.user_validation_rules = Some(extra);
            }
        }

        Ok(ret)
    }
}
