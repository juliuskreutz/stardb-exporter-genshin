use anyhow::Result;
use artifactarium::network::{
    gen::{command_id, proto::AchievementAllDataNotify::AchievementAllDataNotify},
    GamePacket, GameSniffer,
};
use base64::{prelude::BASE64_STANDARD, Engine};
use clap::Parser;
use pcap::{ConnectionStatus, Device};
use std::{collections::HashMap, io::Write, panic::catch_unwind, path::PathBuf, sync::mpsc};

const PACKET_FILTER: &str = "udp portrange 22101-22102";

#[derive(serde::Deserialize)]
struct Id {
    id: u32,
}

#[derive(serde::Serialize)]
struct Export {
    achievements: Vec<u32>,
}

#[derive(Parser)]
struct Args {
    /// Read packets from .pcap file instead of capturing live packets
    #[arg(long)]
    pcap: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if let Err(e) = catch_unwind(|| {
        if let Err(e) = export(&args) {
            println!("{e:?}")
        }
    }) {
        println!("{e:?}")
    }

    println!("Press return to exit...");

    std::io::stdout().flush()?;
    std::io::stdin().read_line(&mut String::new())?;

    Ok(())
}

fn export(args: &Args) -> Result<()> {
    let achievements: Vec<Id> = ureq::get("https://stardb.gg/api/gi/achievements")
        .call()?
        .into_json()?;
    let achievement_ids: Vec<_> = achievements.into_iter().map(|a| a.id).collect();

    let keys = load_keys()?;

    let mut join_handles = Vec::new();
    let (tx, rx) = mpsc::channel();

    if let Some(file) = &args.pcap {
        let file = file.clone();
        let tx = tx.clone();
        let handle = std::thread::spawn(move || capture_file(file, tx));
        join_handles.push(handle);
    } else {
        for device in Device::list()
            .unwrap()
            .into_iter()
            .filter(|d| d.flags.connection_status == ConnectionStatus::Connected)
            .filter(|d| !d.addresses.is_empty())
            .filter(|d| !d.flags.is_loopback())
        {
            let tx = tx.clone();
            let handle = std::thread::spawn(move || capture_device(device, tx));
            join_handles.push(handle);
        }
    }
    drop(tx);

    let mut sniffer = GameSniffer::new().set_initial_keys(keys);

    let mut achievements = Vec::new();

    while let Ok(data) = rx.recv() {
        let Some(GamePacket::Commands(commands)) = sniffer.receive_packet(data) else {
            continue;
        };

        for command in commands {
            if command.command_id == command_id::AchievementAllDataNotify {
                if !achievements.is_empty() {
                    continue;
                }

                println!("Got achievements packet");

                if let Ok(quest_data) = command.parse_proto::<AchievementAllDataNotify>() {
                    for quest in quest_data.achievement_list {
                        if achievement_ids.contains(&quest.id)
                            && (quest.status.value() == 2 || quest.status.value() == 3)
                        {
                            achievements.push(quest.id);
                        }
                    }
                }
            }
        }

        if !achievements.is_empty() {
            break;
        }
    }

    if achievements.is_empty() {
        return Err(anyhow::anyhow!("No achievements found"));
    }

    println!("Copying to clipboard");

    let export = Export { achievements };
    let json = serde_json::to_string(&export)?;

    let mut clipboard = arboard::Clipboard::new()?;
    clipboard.set_text(json)?;

    println!(
        "Copied {} achievements to clipboard",
        export.achievements.len(),
    );

    Ok(())
}

fn load_keys() -> Result<HashMap<u16, Vec<u8>>> {
    let keys: HashMap<u16, String> = serde_json::from_slice(include_bytes!("../keys.json"))?;

    let mut keys_bytes = HashMap::new();

    for (k, v) in keys {
        keys_bytes.insert(k, BASE64_STANDARD.decode(v)?);
    }

    Ok(keys_bytes)
}

fn capture_file(file: PathBuf, tx: mpsc::Sender<Vec<u8>>) -> Result<()> {
    println!("Reading file~!");

    let mut capture = pcap::Capture::from_file(file)?;

    capture.filter(PACKET_FILTER, false)?;

    while let Ok(packet) = capture.next_packet() {
        tx.send(packet.data.to_vec())?;
    }

    Ok(())
}

fn capture_device(device: Device, tx: mpsc::Sender<Vec<u8>>) -> Result<()> {
    loop {
        let mut capture = pcap::Capture::from_device(device.clone())?
            .immediate_mode(true)
            .promisc(true)
            .timeout(0)
            .open()?;

        capture.filter(PACKET_FILTER, true).unwrap();

        println!("All ready~!");

        let mut has_captured = false;

        loop {
            match capture.next_packet() {
                Ok(packet) => {
                    tx.send(packet.data.to_vec())?;
                    has_captured = true;
                }
                Err(_) if !has_captured => break,
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => return Err(anyhow::anyhow!("{e}")),
            }
        }

        println!("Error. Starting up again...");
    }
}
