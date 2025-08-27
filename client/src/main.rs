use crate::process::{ProcessTrait, Win32Process};
use clap::Parser;
use log::error;
use simplelog::{ColorChoice, Config, LevelFilter, TermLogger, TerminalMode};

mod dto;
mod error;
mod process;
mod syringe;

use syringe::*;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, help = "Name of the process to target")]
    process: String,

    #[arg(short, long, help = "ID of the library to inject")]
    library: String,

    #[arg(long, default_value = "http://localhost:3000", help = "Server host address")]
    host: String,

    #[arg(long, help = "Target window class for execution by windows hook")]
    window_class: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let log_level = if cfg!(debug_assertions) {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };

    TermLogger::init(
        log_level,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

    let mut process = match Win32Process::find_process_by_name(&args.process) {
        Ok(process) => process,
        Err(err) => {
            error!("failed to find process \"{}\"", args.process);
            return Err(err.into());
        }
    };

    if let Err(err) = process.attach() {
        error!("failed to attach to process \"{}\"", args.process);
        return Err(err.into());
    }

    let syringe = Syringe::new(&process, args.host);

    let execution_method = ExecutionByWindowsHook {
        window_class: Some(args.window_class.to_string()),
        ..Default::default()
    }
    .into();

    syringe.inject(&args.library, &execution_method)?;

    Ok(())
}
