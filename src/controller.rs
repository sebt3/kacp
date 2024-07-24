use crate::{
    ApplicationCondition, Context, Error, Kacp, KubeAuthenticationConfigurationSpec, Result,
    KACP_FINALIZER,
};
use kube::{
    api::{Api, ListParams},
    runtime::{
        controller::Action,
        events::Reporter,
        finalizer::{finalizer, Event as Finalizer},
    },
    Client,
};
use std::sync::Arc;
use tokio::time::{sleep, Duration};

pub async fn update_config(ctx: Arc<Context>, ignore: Option<&str>) -> Result<()> {
    let client = ctx.client.clone();
    let reporter = Reporter {
        controller: KACP_FINALIZER.to_string(),
        instance: Some(ctx.node.clone()),
    };
    let mut to_write: Vec<KubeAuthenticationConfigurationSpec> = [].to_vec();
    let cfgs: Api<Kacp> = Api::<Kacp>::all(client.clone());
    let node = ctx.node.clone();
    for i in cfgs
        .list(&ListParams::default())
        .await
        .map_err(|e| {
            tracing::warn!("{e}");
            Error::KubeError(e)
        })?
        .into_iter()
        .filter(|i| {
            ignore.is_none()
                || ignore.clone().unwrap().to_string()
                    != i.metadata.name.clone().unwrap_or("no_name".into())
        })
    {
        let gen = i.metadata.generation.unwrap_or(1);
        let mut conditions = i.spec.get_conditions(
            &i.metadata.name.clone().unwrap_or("no_name".to_string()),
            node.as_str(),
            gen,
        );
        if conditions.len() < 1 {
            match ctx.config.clone().apply_to(
                &i.spec,
                &i.metadata.name.clone().unwrap_or("no_name".into()),
            ) {
                Err(e) => {
                    i.send_warning(
                        client.clone(),
                        reporter.clone(),
                        "UpdatingConfig".into(),
                        "Fail".into(),
                        Some(format!("{e}")),
                    )
                    .await;
                    if i.condition_not_failed(&node) {
                        conditions.push(ApplicationCondition::not_ready(
                            &format!("{e}"),
                            &node,
                            gen,
                        ));
                        i.save_status(cfgs.clone(), conditions, &node).await;
                    }
                }
                Ok(item) => {
                    to_write.push(item);
                    if i.condition_not_ready(&node) {
                        conditions.push(ApplicationCondition::is_ready("ok", &node, gen));
                        i.save_status(cfgs.clone(), conditions, &node).await;
                    }
                }
            }
        } else if i.condition_not_failed(&node) {
            conditions.push(ApplicationCondition::not_ready(
                &format!("Others check failed"),
                &node,
                gen,
            ));
            i.save_status(cfgs.clone(), conditions, &node).await;
        }
    }
    let file_content = serde_yaml::to_string(&serde_json::json!({
        "apiVersion": "apiserver.config.k8s.io/v1beta1",
        "kind": "AuthenticationConfiguration",
        "jwt": to_write
    })).unwrap_or("---\napiVersion: apiserver.config.k8s.io/v1beta1\nkind: AuthenticationConfiguration\njwt: []\n".to_string());
    tracing::info!(
        "Saving {} issuers to {}",
        to_write.len(),
        ctx.target
            .as_path()
            .as_os_str()
            .to_str()
            .unwrap_or_default()
    );
    std::fs::write(ctx.target.clone(), file_content).map_err(|e| {
        tracing::warn!("{e}");
        Error::StdIo(e)
    })?;
    Ok(())
}

pub async fn wait_ready(ctx: Arc<Context>) -> Result<()> {
    let client = Client::try_default()
        .await
        .expect("failed to create kube Client");
    let cfgs = Api::<Kacp>::all(client.clone());
    let mut ready = false;
    while !ready {
        if let Err(err) = cfgs.list(&ListParams::default().limit(1)).await {
            tracing::info!("CRD not yet ready ({err}), waiting a minut.");
            sleep(Duration::from_secs(60)).await;
        } else {
            ready = true;
        }
    }
    update_config(ctx, None).await
}

pub async fn reconcile(kacp: Arc<Kacp>, ctx: Arc<Context>) -> Result<Action, Error> {
    let kacps: Api<Kacp> = Api::all(ctx.client.clone());
    finalizer(&kacps, KACP_FINALIZER, kacp, |event| async {
        match event {
            Finalizer::Apply(kacp) => kacp.reconcile(ctx.clone()).await,
            Finalizer::Cleanup(kacp) => kacp.cleanup(ctx.clone()).await,
        }
    })
    .await
    .map_err(|e| Error::FinalizerError(Box::new(e)))
}

#[must_use]
pub fn error_policy(kacp: Arc<Kacp>, error: &Error, _ctx: Arc<Context>) -> Action {
    tracing::warn!("reconcile failed for {:?}: {:?}", kacp.metadata.name, error);
    Action::requeue(Duration::from_secs(5 * 60))
}
