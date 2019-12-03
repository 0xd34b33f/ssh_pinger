use clap::{App, Arg, SubCommand};
use fern::colors::{Color, ColoredLevelConfig};
use log::{debug, error, info, trace, warn};
use std::fs::File;
use std::io::prelude::*;
use std::io::{self, BufReader};
use std::sync::mpsc::channel;
use workerpool::{Pool, Worker};
use workerpool::thunk::{Thunk, ThunkWorker};
use std::net::TcpStream;
use ssh2::Session;
use ssh2::CheckResult::Match;
use std::time::Duration;
use rand::Rng;
use rand::distributions::Alphanumeric;

fn hosts_builder(path: String) -> Vec<String> {
	let file = match File::open(std::path::Path::new(&path)) {
		Ok(a) => a,
		Err(e) => {
			error!("Error opening hosts file: {}", e);
			std::process::exit(1);
		}
	};
	let f = BufReader::new(file);
	let mut hosts = Vec::<String>::new();
	for line in f.lines() {
		let mut l = line.expect("Failed processing str as line");
		if !l.chars().all(char::is_whitespace) {
			l.push_str(":22");
			hosts.push(l);
		};
	}
	println!("len: {}", hosts.len());
	hosts
}

fn connect_host(host: String)
{
	let tcp = match TcpStream::connect(&host) {
		Ok(a) => a,
		Err(e) => {
			warn!("Failed connected to {}:{}", &host, e);
			return;
		}
	};
	tcp.set_read_timeout(Some(Duration::new(1, 0))).unwrap();
	let mut sess = match Session::new() {
		Ok(a) => a,
		Err(e) => {
			warn!("Failed making session on {}:{}", &host, e);
			return;
		}
	};
	sess.set_tcp_stream(tcp);
	match sess.handshake() {
		Ok(_) => (),
		Err(e) => {
			warn!("Failed establishing handshake with {}:{}", &host, e);
			return;
		}
	}
	const LEN: usize = 10;
	let user: String = rand::thread_rng()
		.sample_iter(&Alphanumeric)
		.take(LEN)
		.collect();
	let passwd: String = rand::thread_rng()
		.sample_iter(&Alphanumeric)
		.take(LEN)
		.collect();
	match sess.userauth_password(
		user.as_str(),
		passwd.as_str(),
	) {
		Ok(_) => (),
		Err(e) => {
			debug!("Done for: {}", &host);
		}
	}
}

#[derive(Default)]
struct Fool
{
}

impl Worker for Fool {
	type Input = String;
	type Output = ();
	
	fn execute(&mut self, inp: Self::Input) -> Self::Output {
		connect_host(inp)
	}
}

fn process_hosts(hosts: Vec<String>) {
	info!("Started processing hosts");
	let n_workers = 4;
	let pool = Pool::<Fool>::new(n_workers);
	let (tx, rx) = channel();
	for host in hosts {
		let host_name = host.clone();
		pool.execute_to(tx.clone(), host_name);
	}
}

fn main() {
	let matches = App::new("Ssh pinger")
		.version("0.1")
		.arg(
			Arg::with_name("path")
				.short("p")
				.long("path")
				.value_name("PATH")
				.help("Set path to the file with hostnames")
				.required(true),
		)
		.get_matches();
	let path = matches.value_of("path").unwrap().to_string();
	set_up_logging();
	let hosts = hosts_builder(path);
	process_hosts(hosts);
}

fn set_up_logging() {
	// configure colors for the whole line
	let colors_line = ColoredLevelConfig::new()
		.error(Color::Red)
		.warn(Color::Yellow)
		// we actually don't need to specify the color for debug and info, they are white by default
		.info(Color::White)
		.debug(Color::White)
		// depending on the terminals color scheme, this is the same as the background color
		.trace(Color::BrightBlack);
	
	// configure colors for the name of the level.
	// since almost all of them are the some as the color for the whole line, we
	// just clone `colors_line` and overwrite our changes
	let colors_level = colors_line.clone().info(Color::Green);
	// here we set up our fern Dispatch
	fern::Dispatch::new()
		.format(move |out, message, record| {
			out.finish(format_args!(
				"{color_line}[{date}][{target}][{level}{color_line}] {message}\x1B[0m",
				color_line = format_args!(
					"\x1B[{}m",
					colors_line.get_color(&record.level()).to_fg_str()
				),
				date = chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
				target = record.target(),
				level = colors_level.color(record.level()),
				message = message,
			));
		})
		// set the default log level. to filter out verbose log messages from dependencies, set
		// this to Warn and overwrite the log level for your crate.
		.level(log::LevelFilter::Debug)
		// change log levels for individual modules. Note: This looks for the record's target
		// field which defaults to the module path but can be overwritten with the `target`
		// parameter:
		// `info!(target="special_target", "This log message is about special_target");`
		.level_for("pretty_colored", log::LevelFilter::Trace)
		// output to stdout
		.chain(std::io::stdout())
		.apply()
		.unwrap();
	
	debug!("finished setting up logging! yay!");
}
