use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let Some(url) = std::env::args().nth(1) else {
        eprintln!("usage: explicit-reqwest-probe <url>");
        return ExitCode::from(2);
    };

    let client = match reqwest::Client::builder().build() {
        Ok(client) => client,
        Err(err) => {
            eprintln!("build error: {err:#}");
            return ExitCode::FAILURE;
        }
    };

    match client.get(url).send().await {
        Ok(response) => {
            println!("status: {}", response.status());
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("request error: {err:#}");
            ExitCode::FAILURE
        }
    }
}
