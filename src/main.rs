use actix_web::{get, middleware, App, HttpRequest, HttpResponse, HttpServer, Responder};
use clap::Parser;
use controller::{update_config, Configuration, Context, Kacp, Result};
use futures::{FutureExt, StreamExt};
use kube::{
    api::Api,
    client::Client,
    runtime::{
        controller::{Config, Controller},
        watcher,
    },
};
use std::{env, path::PathBuf, sync::Arc};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[arg(
        short,
        long,
        value_name = "TARGET_FILE",
        env = "TARGET_FILE",
        default_value = "/etc/kubernetes/config/AuthenticationConfiguration.yaml"
    )]
    target_file: PathBuf,
    #[arg(
        short,
        long,
        value_name = "CONFIG_FILE",
        env = "CONFIG_FILE",
        default_value = "/etc/kacp/kacp.yaml"
    )]
    config_file: PathBuf,
}

#[get("/health")]
async fn health(_: HttpRequest) -> impl Responder {
    HttpResponse::Ok().json("healthy")
}

static PORT_VAR_NAME: &str = "PORT";

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let app: Args = clap::Parser::parse();
    let node = std::env::var("CONTROLLER_NODE_NAME").unwrap_or("default".into());
    let context = Arc::new(Context::new(
        Client::try_default().await.expect("create client"),
        Configuration::load_from(app.config_file).unwrap_or_else(|e| {
            tracing::warn!("Failed to load configuration: {:?}", e);
            Configuration::new()
        }),
        app.target_file,
        node.as_str(),
    ));

    let cfgs = Api::<Kacp>::all(context.client.clone());
    update_config(context.clone(), None)
        .await
        .unwrap_or_default();
    let controller = Controller::new(cfgs, watcher::Config::default().any_semantic())
        .with_config(Config::default().concurrency(2))
        .shutdown_on_signal()
        .run(
            controller::reconcile,
            controller::error_policy,
            context.clone(),
        )
        .filter_map(|x| async move { std::result::Result::ok(x) })
        .for_each(|_| futures::future::ready(()))
        .boxed();

    let port = if env::var(PORT_VAR_NAME).is_ok() {
        env::var(PORT_VAR_NAME).unwrap()
    } else {
        "8080".to_string()
    };
    let server = HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default().exclude("/health"))
            .service(health)
    })
    .bind(format!("0.0.0.0:{port}"))
    .unwrap()
    .shutdown_timeout(5);

    tokio::select! {
        _ = controller => tracing::warn!("kacp controller exited"),
        _ = server.run() => tracing::info!("actix exited"),
    }
    Ok(())
}
